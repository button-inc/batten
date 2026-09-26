# Does this host carry enough independent session transcripts to measure a
# prose-shaped literal over (CLOUD-388, CLOUD-651, ported off
# `mise-tasks/transcript-corpus-check.sh` under CLOUD-1717).
#
# WHY THE CONDITION EXISTS AT ALL. This repository holds prose-shaped predicates
# to one method: no literal ships until it is measured over a real corpus,
# counting firings AND true positives among them (CLOUD-252, then CLOUD-323 over
# 60 merged PR bodies). For PR bodies the corpus is GitHub and one API call. For
# SESSION TRANSCRIPTS there was no corpus, and the reason was the environment
# rather than anyone's oversight: transcripts are written inside a session's own
# ephemeral container and destroyed with it. CLOUD-326's section 8.1 states its
# unblock condition as "N independent session transcripts", and a block written
# as prose is a block no gate reads. This pair is that condition as a command and
# an exit code, which is the whole of why it exists.
#
# A REFUSAL HERE IS A PROGRESS READING, NOT A PERMANENT STATE, and this file says
# so because the retired program's first header said the opposite. That version
# called the corpus impossible, on CLOUD-388's ruling that transcript egress was
# out of scope — a POLICY choice about what may leave the container rather than a
# fact about the world. The owner lifted it and transcripts are collected to the
# Batten service, so a low count means the collector has not landed or has not
# reached this host. Do not re-derive the old rule from a low number.
#
# THE SPLIT. The census is `mise-tasks/transcript_census.py`, driven by
# `[tasks.transcript-corpus-record]`: §5 makes `check` `read` and incapable of
# walking a host filesystem. What is left here is the comparison, and it is the
# whole decision.
#
# THE THRESHOLD TRAVELS IN THE RECORD rather than living here, and that is the
# caller's argument preserved. The default is 2 — the weakest non-vacuous bound,
# "more than the session asking", which is the least this can demand and still
# mean anything. A larger constant would look more rigorous and decide nothing
# extra: the measured count is 0 on every container this has run on, so every
# threshold from 1 upward returns the same verdict.
#
# POINTER-ONLY IS A SECURITY PROPERTY OVER THIS INPUT (rule 4), not a style one.
# The record carries two counts and the finding carries two counts; no path, no
# session id, and no byte of any transcript reaches either.
#
#MUTANT-SUITE crates/batten/tests/it/transcript_corpus.rs
#MUTANT thin-corpus-passes|s@^\tsessions < threshold$@\tfalse@|one_transcript_is_one_session_and_one_is_not_a_corpus
#MUTANT torn-record-passes|s@^\tcount(values(label)) != 1$@\tfalse@|a_torn_corpus_record_is_reported_rather_than_passing

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.transcript_corpus

import rego.v1

rules contains "prose measure partial"

# The record, or nothing. ABSENT IS NOT EMPTY: a host whose producer never ran
# has no key here, Rego reads that as *does not hold*, and the rule is silent.
# The producer writes nothing when the transcript root does not exist, which is
# the question not being askable — distinct from a root that was walked and held
# no transcripts, which is the answer zero.
lines := input.tree.records["transcript-corpus"]

# Every numeric reading on the record, as a SET of `[label, value]` pairs.
#
# A PARTIAL SET, NOT A FUNCTION, and the difference was a live fault: `counted`
# used to bind `some line in lines` inside a function body, so two `sessions`
# lines with DIFFERENT values bound two outputs and regorus raised
# `eval_conflict_error` — which the engine reads as a module fault, silencing
# every predicate here at exit 0. `task-callable.rego` states the same rule for
# its own reader. A set cannot conflict; it can only hold more than one value,
# and that is now decided below rather than faulting.
readings contains [label, to_number(raw)] if {
	some line in lines
	some label in {"sessions", "threshold"}
	startswith(line, concat("", [label, " "]))
	raw := trim_space(substring(line, count(label) + 1, -1))
	regex.match(data.batten.patterns["whole-number"], raw)
}

values(label) := {value | some [l, value] in readings; l == label}

# Exactly one value, or no value at all.
counted(label) := value if {
	count(values(label)) == 1
	some value in values(label)
}

violation contains {
	"rule": "prose measure partial",
	"verdict": "prose measure partial",
	"subjects": [{"count": sessions}, {"count": threshold}],
} if {
	sessions := counted("sessions")
	threshold := counted("threshold")
	sessions < threshold
}

# A TORN RECORD IS THE SAME READING, NOT A PASS. With two different session
# counts on file, or a record present with either number missing, this host has
# not SHOWN the sessions the caller asked for — which is exactly this class's
# gloss. Silence here would be a producer bug reading as a sufficient corpus.
violation contains {
	"rule": "prose measure partial",
	"verdict": "prose measure partial",
	"subjects": [{"count": count(values("sessions"))}],
} if {
	lines
	some label in {"sessions", "threshold"}
	count(values(label)) != 1
}

# --- cases -------------------------------------------------------------------

test_one_transcript_is_one_session_and_one_is_not_a_corpus if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 1",
		"threshold 2",
	]}}}
	count(found) == 1
}

test_an_empty_root_is_zero_which_is_an_answer if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 0",
		"threshold 2",
	]}}}
	count(found) == 1
}

test_three_distinct_sessions_satisfy_the_default_threshold if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 3",
		"threshold 2",
	]}}}
	count(found) == 0
}

# THE THRESHOLD IS THE CALLER'S, so the same corpus can fail a stricter one.
test_the_threshold_is_the_argument if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 3",
		"threshold 5",
	]}}}
	count(found) == 1
}

# The boundary is inclusive: meeting the threshold exactly is meeting it.
test_meeting_the_threshold_exactly_is_clean if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 2",
		"threshold 2",
	]}}}
	count(found) == 0
}

test_an_absent_record_says_nothing_rather_than_refusing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}

# A torn record — the producer never writes one without the other. This case
# used to assert `count(found) == 0`, pinning a silence where the record is
# present and the corpus unshown. The comparison is still not made on half a
# reading; the record is reported as the partial reading it is.
test_a_record_missing_a_column_decides_nothing if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": ["sessions 0"]}}}
	found == {{"rule": "prose measure partial", "verdict": "prose measure partial", "subjects": [{"count": 1}]}}
}

# THE FAULT THIS SET EXISTS TO REMOVE: two different session counts used to
# raise `eval_conflict_error` at evaluation. It now evaluates, and reports.
test_two_conflicting_session_counts_are_a_finding_not_a_fault if {
	found := violation with input as {"tree": {"records": {"transcript-corpus": [
		"sessions 1",
		"sessions 5",
		"threshold 2",
	]}}}
	found == {{"rule": "prose measure partial", "verdict": "prose measure partial", "subjects": [{"count": 2}]}}
}
