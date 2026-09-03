# Re-asking is not waiting (CLOUD-1341).
#
# AGENTS.md already states the invariant — "The exit notification IS the wake-up;
# waiting for it costs nothing… 'idle' means a turn with NOTHING backgrounded" —
# and for this family it was prose, which non-negotiable rule 2 calls half a
# change. Two landed arms sit next to this one and neither can reach it:
# `run-shape`'s refusal keys on a backgrounded `sleep`, and CLOUD-489's on
# `until`/`while` inside one command string. A poll spread ACROSS TURNS carries
# neither token, and where the tool is a harness verb with no argv there is no
# `segments` entry for a `shape` row to match either.
#
# WHAT THE FACT IS, AND IT IS A MAXIMUM RATHER THAN A TOTAL.
# `input.facts.extracted.repeats` is the recurrence count of the session's
# MOST-REPEATED call identity — same tool, same arguments — and not a sum over
# every identity. The invariant is exact: a call you have already made, with the
# same arguments, told you what it told you the first time. The engine computes
# it from typed events; no byte of the session reaches a module here, which is
# what keeps this family inside rule 4.
#
# THE SUM IS THE DEFECT THIS ROW SHIPPED ONCE, and the distinction is the whole
# reason the sentence above is emphatic. A running total over every identity is
# monotonic in the length of the session: it never resets, so it fires on any
# session long enough to repeat anything, and a threshold derived from ONE
# identity's recurrence applied to that total is not a threshold at all. The
# fact is a max; the numbers below were always per identity.
#
# THE FIRST DRAFT OF THIS PREDICATE COULD NOT DISCRIMINATE, and the measurement
# is why it was replaced rather than tuned. It proposed "consecutive calls to one
# tool with no intervening state change". Measured over a real transcript, the
# polling arrived in 249 separate bursts whose longest run was 8 — a length any
# healthy session reaches — so a consecutive-run reading would have shipped as
# coverage while deciding nothing, which is precisely the failure CLOUD-418
# exists to catch. The per-identity recurrence separates: 1079 against a healthy
# ceiling of 38, because it does not care what sits between two identical calls.
#
# THE THRESHOLD IS MEASURED RATHER THAN CHOSEN, and it lives here because this
# is a CONSUMER module. Same transcript: the worst identity recurred 1079 times
# and the next-most-repeated 38, so any constant between them decides; 100 sits
# 2.6x clear of the healthy ceiling and 10.8x below the defect. A guess is what
# CLOUD-199 measured getting a guard bypassed, so the number travels with its
# measurement rather than alone.
#
# NOT a `[[pattern]]` row, and not a `batten.toml` value: `.claude/rules/
# policy-modules.md` refuses a threshold spelled as a pattern outright, and the
# only consumer surface a module can read today is `data.batten.patterns`. A
# constant in a `policy/*.rego` module is the consumer's own number in the
# consumer's own file — the same shape `ci-parity.rego` uses for this
# repository's check roster — and non-negotiable rule 1 is about
# `crates/batten`, which this is not. A preset could not do this and would have
# to take the number some other way.
#
# IT SHIPS AT `warn`, AND THAT IS A DECISION RATHER THAN CAUTION. A
# `mediated_call` row at `deny` refuses EVERY subsequent tool call once it
# fires, and there is no recovery inside the session that trips it: `batten
# override request` and `spend` are themselves mediated calls, so an admission
# cannot clear a `mediated_call` deny — requesting one requires making the call
# the deny refuses. This row was landed at `deny` once and locked its own
# authoring session out at count ~1300, push included. Promotion needs this
# predicate shown SILENT against a real transcript first; a mutation proves the
# predicate discriminates, never that the constant is right.
#
# COULD-NOT-LOOK IS THE COMMON CASE, exactly as `denials-outlive-the-turn`
# records: transcripts die with their container, and four states are null — no
# path on the envelope, a host that keeps none, a file that will not parse, and
# nobody having declared an extractor. Every one differs from an extractor that
# ran and counted zero, so the body requires a real count and reads null as
# nothing rather than as innocence.
#MUTANT-SUITE crates/batten/tests/it/extracted_facts.rs
#MUTANT repeats-may-go-unpriced|s@^	input.facts.extracted.repeats > threshold$@	false@|a_session_that_re_asks_past_the_threshold_is_refused

# METADATA
# description: |
#   Bound to the MEDIATED CALL: this row is `scope = "mediated_call"`, so it
#   reads `input.call` and `input.facts` and never the tree document.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.a_repeated_call_is_not_progress

import rego.v1

rules contains "a-repeated-call-is-not-progress"

# The consumer's number. See the header for the measurement behind it.
threshold := 100

# A REAL COUNT, over a declared threshold. `is_object` is the null guard: an
# absent extractor object makes every field undefined, and Rego reads undefined
# as does-not-hold, so the arm goes quiet rather than refusing a session nobody
# could look at.
violation contains {
	"rule": "a-repeated-call-is-not-progress",
	"verdict": "turn ask twice",
	"subjects": [{"count": input.facts.extracted.repeats}],
} if {
	is_object(input.facts.extracted)
	input.facts.extracted.repeats > threshold
}

# The predicate's own tests. The SILENT cases carry the weight here for the usual
# reason: this is a refusal, so a module that fired on everything would satisfy
# the deny case while deciding nothing.

session(extracted) := {"call": {"command": ""}, "facts": {"extracted": extracted}}

test_a_session_that_re_asks_past_the_threshold_is_refused if {
	some v in violation with input as session({"repeats": 1079})
	v.verdict == "turn ask twice"
}

# THE COUNT IS THE POINTER, never a tool name and never a span of the session —
# rule 4 decided in the finding's shape rather than by a filter downstream.
test_the_finding_carries_a_count_and_nothing_else if {
	some v in violation with input as session({"repeats": 1079})
	v.subjects == [{"count": 1079}]
}

# AT the threshold is not past it. Stated as a case because an off-by-one here
# moves the whole population the rule fires on.
test_the_threshold_itself_is_clean if {
	count(violation) == 0 with input as session({"repeats": 100})
}

# The healthy arm, at the measured ceiling. Without this the rule could fire on
# every busy session and still pass the case above it.
test_a_busy_but_productive_session_is_clean if {
	count(violation) == 0 with input as session({"repeats": 38})
}

# COULD NOT LOOK IS NOT INNOCENCE, and it is not guilt either.
test_no_transcript_is_not_a_clean_session if {
	count(violation) == 0 with input as session(null)
}

test_an_undeclared_extractor_yields_nothing if {
	count(violation) == 0 with input as session({"turns": 9})
}

# JUST PAST THE THRESHOLD STILL FIRES. The case above pins the boundary from
# below; without this one an off-by-one in the other direction would pass both.
test_one_over_the_threshold_is_refused if {
	some v in violation with input as session({"repeats": 101})
	v.verdict == "turn ask twice"
}

# A COMPOUND COMMAND REACHES THE SAME VERDICT, and the case exists even though
# this predicate never reads the command line. CLOUD-857 measured a module that
# anchored on `input.call.command` denying `git push --force origin main` while
# allowing `cd /tmp && git push --force origin main`, with a green suite over it
# — so `policy test` refuses a mediated-call suite whose every case passes a bare
# command. Here the case is a STANDING guarantee rather than a repair: the
# verdict is a function of the fact alone, and this is what would go red if some
# later revision started reading the command and anchored it wrongly.
test_a_compound_command_reaches_the_same_verdict if {
	some v in violation with input as {
		"call": {"command": "cd /tmp && mise run land"},
		"facts": {"extracted": {"repeats": 1079}},
	}
	v.verdict == "turn ask twice"
}
