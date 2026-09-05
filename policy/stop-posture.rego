# The one output-posture tell AGENTS.md names literally, as a module rather than
# a Stop hook body (CLOUD-97, ported under CLOUD-1051).
#
# A hedged flag is a finding written as editorial instead of durably. Chat stores
# nothing, so the finding's home is an issue or a memory — and the sentence that
# flags it in passing is the double-write CLOUD-200 and CLOUD-248 exist to kill.
#
# THIS IS THE FIRST OF `stop-guard`'s FIVE RULES TO MOVE, and it is first because
# it is the only one expressible from the projection alone: `input.call
# ["final-message"]` is the turn's own text, so no fact and no spawn is needed.
# The other four read the transcript, the store and the board record, and follow
# with the facts they need.
#
# PRECEDENCE IS THE MODULE'S, NOT THE ENGINE'S, which is why this is Rego at all.
# `stop-guard` emits at most one nudge per turn — "two nudges on one turn is how a
# channel stops being read" — and ranks its rules by MEASURED precision: this one
# leads at 3/3 against `finding-sink-check`'s 1/1, with three unmeasured rules
# below. When the remaining four arrive they compose here, where the ranking is
# readable data, rather than in declaration order in a TOML table.
#
# A REFUSAL AT `Stop` IS ADVICE, and that is the engine's existing rule rather
# than anything this module asks for: `Event::carries_a_verdict` is the one
# authority both producers ask, and `Stop` carries none. So a `deny` here reaches
# the nudge channel and cannot refuse a turn — the property CLOUD-97 and CLOUD-219
# each ruled on independently, preserved by construction instead of by care.
#
# THE SCRUB IS FOUR SUBSTITUTIONS AND IT COMES FIRST, because a tell inside a
# quotation is a report OF the tell rather than an instance of it. This file
# documented its own rule twice before the shell's scrubber covered quoted spans.
# Fenced blocks, code spans, double-quoted spans and block quotes all come out.
#
# WHOLE-INPUT, NEVER LINE-AT-A-TIME. Every one of those spans is routinely
# line-wrapped in real prose, so a line-based reader leaves the interior of a
# wrapped quotation exposed. A Rego string is the whole input by construction,
# which is what the shell needed `perl -0777` for.
#
# THE LITERAL SET IS AGENTS.md's OWN TWO EXAMPLES PLUS THEIR DIRECT INFLECTIONS,
# and its width is measured rather than chosen. `worth naming` is the witnessed
# miss: the CLOUD-347..356 audit closed with "One open thread worth naming: the
# census never interrogated host settings" — a real finding that reached chat and
# nothing else, and became CLOUD-380 only because a human asked. That sentence was
# silent while the same sentence with `noting` fired. `calling out` stays OUT:
# unwitnessed, and admitting it would be the unmeasured-literal invention
# CLOUD-323 and CLOUD-326 forbid.
#MUTANT-SUITE crates/batten/tests/it/stop_posture.rs
#MUTANT hedge-unread|s@^\thits > 0$@\tfalse@|a_hedged_final_message_reaches_the_host_advisory_channel

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: this row is `scope = "mediated_call"`, so
#   it reads `{call, facts}` and never the tree document.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.stop_posture

import rego.v1

rules contains "stop-posture"

# The turn's final text, or the empty string when this is not a Stop.
#
# A `default` rule with an `is_string` guard, and `object.get`'s default is NOT
# enough — which is the same null-is-not-absent distinction this engine draws
# everywhere else, arriving in Rego. `object.get` substitutes its default when the
# PATH is missing; every non-Stop event projects the key with an explicit `null`,
# so the path is present, the default never applies, and `regex.replace` faults on
# a null argument. Measured: that is exactly how this module first failed.
#
# The guard is `is_string` rather than `!= null` so a host that ever sends a
# number or an object here is silent too, rather than faulting at the first
# substitution.
default message := ""

message := text if {
	text := input.call["final-message"]
	is_string(text)
}

# What a scrubbed span becomes. One token for all four, because the substitution
# only has to leave something that is not prose — the shell used three names and
# the difference never carried meaning.
#
# BOUND RATHER THAN WRITTEN INLINE, and not to satisfy a linter. `check_no_inline_regex`
# reads EVERY string literal handed to a `regex.*` builtin, deliberately: the
# builtins disagree on argument order, so a per-builtin position table would be a
# second thing to keep in step with upstream. A replacement is not a pattern, so
# naming it is how this module says which of the two it is — the value has a home
# and the gate's over-approximation stays intact rather than being narrowed for
# one caller's convenience.
elided := "ELIDED"

# THE SCRUB, in the shell's order, which is load-bearing: fenced blocks before
# code spans, because a fence contains backticks and stripping the spans first
# would leave the fence's own delimiters behind to pair with prose.
scrubbed := s4 if {
	s1 := regex.replace(message, data.batten.patterns["md-fenced-block"], elided)
	s2 := regex.replace(s1, data.batten.patterns["md-code-span"], elided)
	s3 := regex.replace(s2, data.batten.patterns["md-quoted-span"], elided)
	s4 := regex.replace(s3, data.batten.patterns["md-block-quote"], elided)
}

# Every hedge in the scrubbed text.
#
# MATCHES, NOT MATCHING LINES. The shell's own test caught that distinction: two
# tells in one sentence counted as one under `grep -c`, which understates exactly
# the double-write this rule exists to name.
hits := count(regex.find_n(data.batten.patterns["hedged-flag-framing"], scrubbed, -1))

# THE NUDGE. A count and nothing else — non-negotiable rule 4, and load-bearing
# here rather than decorative: handing the matched prose back would make this a
# mirror, and a mirror is cleared by restating it, which is the double-write.
violation contains {
	"rule": "stop-posture",
	"verdict": "prose report duplicate",
	"subjects": [{"count": hits}],
} if {
	hits > 0
}

# The predicate's own tests. The SILENT cases are the load-bearing half: a rule
# that fired on every turn would satisfy the deny above and nudge about nothing.

ending(text) := {"call": {"final-message": text}}

test_a_hedged_flag_is_named if {
	some v in violation with input as ending("One thing I would flag is the exit code.")
	v.verdict == "prose report duplicate"
}

test_the_witnessed_miss_fires if {
	# `worth naming` — the sentence that reached chat and nothing else, and became
	# CLOUD-380 only because a human asked.
	some v in violation with input as ending("One open thread worth naming: the census never interrogated host settings.")
	v.verdict == "prose report duplicate"
}

test_both_openers_share_one_verb_set if {
	# CLOUD-387's asymmetry: `mentioning` was a flagging verb under one opener and
	# unknown under the other, so the pair is asserted rather than one of them.
	some v in violation with input as ending("It bears mentioning that this is worth mentioning.")
	v.verdict == "prose report duplicate"
}

# THE INFINITIVE OPENER (CLOUD-487), and the three cases together are what make
# the widening additive rather than a rewrite: the new form fires, the
# first-person form it was derived from still fires, and the verb boundary that
# keeps this from becoming "any use of the word" is unmoved.
test_the_infinitive_opener_fires if {
	# The witnessed miss: the same act, one word shorter, and the spelling an agent
	# reaches for when the finding is addressed to somebody else.
	some v in violation with input as ending("One thing to flag for whoever owns CLOUD-291: the lease is stale.")
	v.verdict == "prose report duplicate"
}

test_the_first_person_opener_still_fires_beside_it if {
	# ANTI-VACUITY for the widening: a rewrite that replaced the pronoun branch
	# instead of joining it would pass the case above and lose this one.
	some v in violation with input as ending("One thing I'd note is the exit code.")
	v.verdict == "prose report duplicate"
}

test_an_infinitive_that_is_not_a_flagging_verb_is_silent if {
	# THE NARROWNESS BOUNDARY, and the reason the verb set did not widen with the
	# opener: an entry names an act of FLAGGING, so a plan to do something is not
	# one however the sentence opens.
	count(violation) == 0 with input as ending("One thing to check is whether the exit code is 2.")
}

# THE SCRUB, and each case is a span the shell's first version leaked through.
test_a_tell_inside_a_code_span_is_a_report_of_it if {
	count(violation) == 0 with input as ending("The gate fires on `worth noting`.")
}

test_a_tell_inside_a_quotation_is_a_report_of_it if {
	count(violation) == 0 with input as ending("The rule names \"one thing I would flag\" as its example.")
}

test_a_tell_inside_a_block_quote_is_a_report_of_it if {
	count(violation) == 0 with input as ending("The refusal reads:\n> worth noting, this is hedged\nand that is the tell.")
}

test_a_tell_inside_a_fenced_block_is_a_report_of_it if {
	count(violation) == 0 with input as ending("```\nworth noting\n```")
}

# A WRAPPED QUOTATION, which is the case the line-at-a-time reader leaked and the
# reason the whole-input model is stated rather than assumed.
test_a_wrapped_quotation_is_scrubbed_whole if {
	count(violation) == 0 with input as ending("The rule names \"one thing\nI would flag\" as its example.")
}

# THE NARROWNESS, and these are what keep the rule from firing on ordinary prose.
# Every entry names an ACT OF FLAGGING rather than any use of "note" or "flag".
test_an_ordinary_use_of_note_is_not_a_hedge if {
	count(violation) == 0 with input as ending("I noted the exit code and moved on.")
}

test_an_ordinary_use_of_flag_is_not_a_hedge if {
	count(violation) == 0 with input as ending("The --flag argument is undocumented.")
}

test_calling_out_is_deliberately_outside_the_set if {
	# Unwitnessed, and admitting it would be inventing a phrase list rather than
	# completing an inflection.
	count(violation) == 0 with input as ending("One thing worth calling out is the exit code.")
}

# A CLEAN TURN IS SILENT, which is the common case and the one the channel's
# credibility rests on.
test_a_clean_final_message_says_nothing if {
	count(violation) == 0 with input as ending("Landed and pushed; CI is green.")
}

# NOT A STOP, so there is no final message and nothing to judge. `null` here is
# what every other event projects, and reading it as the empty string is what
# keeps this module from erroring its way to silence by accident.
test_a_tool_call_carries_no_final_message if {
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "final-message": null}}
}

# TWO TELLS IN ONE SENTENCE COUNT TWICE, which `grep -c` got wrong and which
# understates the very thing being measured.
test_the_count_is_over_matches_not_lines if {
	some v in violation with input as ending("Worth noting the first, and it bears noting the second.")
	v.subjects == [{"count": 2}]
}
