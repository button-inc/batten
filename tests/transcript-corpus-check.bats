#!/usr/bin/env bats
# transcript-corpus-check: is there a corpus of independent session transcripts?
# (CLOUD-388)
#
# A live host answers this ONE way — its own session and nothing else — so a
# suite that could not vary the root would ship as coverage while exercising a
# single row (CLOUD-418). `BATTEN_TRANSCRIPT_ROOT` is injected throughout, and
# the rows below are the counts a real host never produces: zero, three, a
# subagent stream that must not inflate the count, and two files carrying one
# session.
#
# The fixture content carries a distinctive token on purpose. The last row
# asserts the emitted bytes do not contain it — pointer-only is a SECURITY
# property over this input rather than a style one, and asserting it is what
# stops a later edit turning a count into a quotation.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/transcript-corpus-check"
	ROOT="$BATS_TEST_TMPDIR/projects"
	mkdir -p "$ROOT"
	export BATTEN_TRANSCRIPT_ROOT="$ROOT"
	# Never inherit the host's. A row that passes because the runner happened to
	# export a session id is a row that discriminates nothing.
	unset BATTEN_SESSION_ID
	FIXTURE_TOKEN="pomegranate-carburettor"
}

# A transcript with one authored, non-sidechain user turn: the shape that opens
# a real session.
session() { # session <file> <session-id>
	printf '%s\n' \
		"{\"type\":\"user\",\"sessionId\":\"$2\",\"message\":{\"role\":\"user\",\"content\":\"$FIXTURE_TOKEN\"}}" \
		"{\"type\":\"assistant\",\"sessionId\":\"$2\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"$FIXTURE_TOKEN\"}]}}" \
		>"$ROOT/$1"
}

# --- the count -----------------------------------------------------------------

@test "an empty root is zero independent sessions, which is an answer and not a failure to look" {
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"transcript-corpus independent=0 min=2"* ]]
}

@test "one transcript is one session, and one is not a corpus" {
	session only.jsonl s-1
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=1 min=2"* ]]
}

@test "three distinct sessions satisfy the default threshold" {
	session a.jsonl s-1
	session b.jsonl s-2
	session c.jsonl s-3
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"independent=3 min=2"* ]]
}

@test "the threshold is the argument, so the same corpus can fail a stricter one" {
	session a.jsonl s-1
	session b.jsonl s-2
	run "$CHECK" 2
	[ "$status" -eq 0 ]
	run "$CHECK" 3
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=2 min=3"* ]]
}

# --- what does not count -------------------------------------------------------

@test "a subagent stream is not an independent session" {
	# CLOUD-326 §8.1 recorded one session plus five subagent transcripts and
	# correctly called that N=1. Every record here is a sidechain.
	printf '%s\n' \
		"{\"type\":\"user\",\"sessionId\":\"sub-1\",\"isSidechain\":true,\"message\":{\"role\":\"user\",\"content\":\"$FIXTURE_TOKEN\"}}" \
		>"$ROOT/sub.jsonl"
	session real.jsonl s-1
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=1 min=2"* ]]
}

@test "a transcript carrying only tool results has nobody in it" {
	# A `tool_result` arrives as a user record and is the harness handing work
	# back. Counting it would make a session out of a transcript no person drove.
	printf '%s\n' \
		"{\"type\":\"user\",\"sessionId\":\"s-9\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"t1\",\"content\":\"$FIXTURE_TOKEN\"}]}}" \
		>"$ROOT/results.jsonl"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=0"* ]]
}

@test "two files carrying one session are one session" {
	session first.jsonl s-1
	session second.jsonl s-1
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=1"* ]]
}

@test "a line this build cannot decode yields nothing rather than a failure to look" {
	# The format is a host's and it moves. A gate that reddened on an unknown or
	# truncated line would be switched off within a release.
	session good.jsonl s-1
	printf '%s\n' 'not json at all' "{\"type\":\"queue-operation\",\"content\":\"$FIXTURE_TOKEN\"}" \
		>"$ROOT/odd.jsonl"
	run "$CHECK" 1
	[ "$status" -eq 0 ]
	[[ "$output" == *"independent=1 min=1"* ]]
}

# --- the asking session ---------------------------------------------------------

@test "excluding the asking session turns its own transcript into zero" {
	session mine.jsonl s-mine
	run "$CHECK" 2 s-mine
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=0"* ]]
}

@test "the exclusion defaults from the environment when no argument names one" {
	session mine.jsonl s-mine
	session other.jsonl s-other
	BATTEN_SESSION_ID=s-mine run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"independent=1"* ]]
}

@test "an explicitly empty exclusion excludes nothing, and does not fall back to the environment" {
	# Absent and empty are different claims: a caller passing "" is saying
	# "count everything", and silently substituting the ambient session id would
	# answer a question nobody asked.
	session mine.jsonl s-mine
	BATTEN_SESSION_ID=s-mine run "$CHECK" 1 ""
	[ "$status" -eq 0 ]
	[[ "$output" == *"independent=1 min=1"* ]]
}

# --- could not look ------------------------------------------------------------

@test "an absent root is exit 2, never a verdict about a corpus nobody looked at" {
	export BATTEN_TRANSCRIPT_ROOT="$BATS_TEST_TMPDIR/nowhere"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not be asked"* ]]
}

@test "a malformed threshold is exit 2" {
	run "$CHECK" two
	[ "$status" -eq 2 ]
	run "$CHECK" ""
	[ "$status" -eq 2 ]
}

@test "more arguments than the contract names is exit 2" {
	run "$CHECK" 2 s-1 extra
	[ "$status" -eq 2 ]
}

# --- the output contract ---------------------------------------------------------

@test "the report is two counts and carries no byte of any transcript" {
	session a.jsonl s-1
	session b.jsonl s-2
	run "$CHECK"
	[ "$status" -eq 0 ]
	# Not the content, not the session ids, not the paths. A count and a count.
	[[ "$output" != *"$FIXTURE_TOKEN"* ]]
	[[ "$output" != *"s-1"* ]]
	[[ "$output" != *"a.jsonl"* ]]
	[[ "$output" != *"$ROOT"* ]]
}

@test "the refusal names what would raise the number, not just the arithmetic" {
	# "0 < 2" sends a reader looking for a way around the gate. What they need is
	# the mechanism that feeds this reading, so they can check whether it ran.
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"collector"* ]]
	[[ "$output" == *"mem:prior-art-and-issue-hygiene"* ]]
}

@test "the refusal does not tell the reader the count can never rise" {
	# The retired rule (CLOUD-388's first verdict) said transcript egress was out
	# of scope, so the corpus could never accumulate. That was policy, not
	# physics, and it was lifted — a refusal that still says "waiting raises
	# nothing" would send the next reader to re-derive a rule nobody holds.
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"waiting raises nothing"* ]]
	[[ "$output" != *"does not accumulate"* ]]
}
