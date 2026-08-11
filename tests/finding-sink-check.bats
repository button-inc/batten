#!/usr/bin/env bats
# CLOUD-252. The stranded finding: a turn cites `path:line` evidence and writes
# nothing durable, so the finding dies with the chat.
#
# The sibling `stop-posture-check` catches the finding written TWICE. This catches
# the one written NOWHERE, which is worse and which the shipped rule cannot see —
# it reads `last_assistant_message`, under half a turn's assistant prose.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/finding-sink-check"
	T="$BATS_TEST_TMPDIR/transcript.jsonl"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# One record per line, the shape the harness actually writes. `prompt` opens a
# turn; `say`/`tool` attach to the turn already open.
prompt() { jq -nc --arg t "${1:-go}" '{type:"user",isSidechain:false,message:{content:$t}}' >>"$T"; }
say() { jq -nc --arg t "$1" '{type:"assistant",isSidechain:false,message:{content:[{type:"text",text:$t}]}}' >>"$T"; }
tool() { jq -nc --arg n "$1" '{type:"assistant",isSidechain:false,message:{content:[{type:"tool_use",name:$n,input:{}}]}}' >>"$T"; }
# A tool_result arrives as a user record and is NOT a prompt — counting it would
# split one turn into several and give each fragment its own verdict.
result() { jq -nc '{type:"user",isSidechain:false,message:{content:[{type:"tool_result",content:"ok"}]}}' >>"$T"; }
sub() { jq -nc --arg t "$1" '{type:"assistant",isSidechain:true,message:{content:[{type:"text",text:$t}]}}' >>"$T"; }
sub_tool() { jq -nc --arg n "$1" '{type:"assistant",isSidechain:true,message:{content:[{type:"tool_use",name:$n,input:{}}]}}' >>"$T"; }

check() { printf '%s' "$T" | "$CHECK"; }

@test "THE STRANDED FINDING: path:line evidence with no durable write is reported" {
	prompt
	say 'The guard is wrong at mise-tasks/land:200 and nothing covers it.'
	run check
	[ "$status" -eq 1 ]
	[[ "$output" == *"turn:1 finding-without-durable-write"* ]]
}

@test "the same turn with a tracker write is clean" {
	prompt
	say 'The guard is wrong at mise-tasks/land:200 and nothing covers it.'
	tool "mcp__Linear__save_issue"
	run check
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "prose with no path:line is clean — ordinary conversation is not noise" {
	prompt
	say 'Rebased onto main and pushed. The gate is green and the PR is open.'
	run check
	[ "$status" -eq 0 ]
}

@test "a durable write counts under the UUID prefix, not only the readable alias" {
	# CLOUD-178: the same connector appears under both names within one session,
	# so an anchor on the server prefix silently misses whichever is live. This is
	# the case that fails if the match is ever moved off the suffix.
	prompt
	say 'Broken at crates/batten/src/config.rs:42.'
	tool "mcp__4db58e41-cd4e-4818-8922-46cf616593f4__save_issue"
	run check
	[ "$status" -eq 0 ]
}

@test "a memory write counts as durable too, not only the tracker" {
	prompt
	say 'Recorded the trap at .serena/memories/core.md:12.'
	tool "mcp__serena__write_memory"
	run check
	[ "$status" -eq 0 ]
}

@test "a read-only tool call is not a durable write" {
	# The conjunct is *durable*, not *any tool use*. A turn that greps and reports
	# is exactly the stranded case.
	prompt
	say 'Found it at mise-tasks/released:82.'
	tool "Bash"
	tool "mcp__Linear__get_issue"
	run check
	[ "$status" -eq 1 ]
	[[ "$output" == *"turn:1"* ]]
}

@test "a subagent's write is not credited to the orchestrator's turn" {
	# Nor is its prose judged as the orchestrator's. Both sides of the exclusion,
	# because crediting either way would be wrong.
	prompt
	say 'Broken at crates/batten/src/git.rs:100.'
	sub_tool "mcp__Linear__save_issue"
	run check
	[ "$status" -eq 1 ]
	[[ "$output" == *"turn:1"* ]]
}

@test "a subagent's prose is not judged as the orchestrator's" {
	prompt
	say 'Rebased and pushed.'
	sub 'The subagent found something at crates/batten/src/lint.rs:7.'
	run check
	[ "$status" -eq 0 ]
}

@test "a tool_result does not open a new turn" {
	# If it did, this one turn would split and the fragment carrying the write
	# would clear while the fragment carrying the prose fired.
	prompt
	say 'Broken at mise-tasks/land:200.'
	tool "Bash"
	result
	tool "mcp__Linear__save_issue"
	run check
	[ "$status" -eq 0 ]
}

@test "POINTER, NEVER PAYLOAD: the report carries no byte of the prose" {
	# The whole design in one assertion. Handing the prose back makes this a
	# mirror, and a mirror is cleared by restating rather than by re-deriving.
	prompt
	say 'The defect is at mise-tasks/land:200 — SENTINELXYZZY is the distinctive marker.'
	run check
	[ "$status" -eq 1 ]
	[[ "$output" != *"SENTINELXYZZY"* ]]
	[[ "$output" != *"The defect is at"* ]]
}

@test "ONLY THE LAST TURN is judged — an earlier stranding is not re-reported" {
	# The defect the live wiring exposed on its first firing: judging the whole
	# transcript reported a turn from hours earlier whose findings were long since
	# filed, and would have re-reported it at every Stop for the rest of the
	# session. A stale pointer is unactionable, so it trains the reader to skip the
	# channel — the exact failure this mechanism exists to avoid.
	prompt
	say 'Broken at mise-tasks/land:200.'
	prompt
	say 'Fixed and pushed, nothing further.'
	run check
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a stranding in the last turn fires even when earlier turns were clean" {
	# The other direction, so the narrowing cannot collapse into never firing.
	prompt
	say 'Rebased and pushed.'
	prompt
	say 'Broken at mise-tasks/land:200.'
	run check
	[ "$status" -eq 1 ]
	[[ "$output" == *"turn:2"* ]]
}

@test "a path:line-looking string that is not a source file does not fire" {
	# The anchor is the extension set this tree carries. Without it, a time or a
	# ratio in prose reads as evidence and the gate becomes noise.
	prompt
	say 'The run took 12:30 and the ratio was 3:1.'
	run check
	[ "$status" -eq 0 ]
}

@test "an unparseable transcript exits 2 — could not look is not a verdict" {
	printf 'this is not json\n' >"$T"
	run check
	[ "$status" -eq 2 ]
}

@test "an absent transcript path exits 2, not 0" {
	run bash -c "printf '%s' '$BATS_TEST_TMPDIR/nope.jsonl' | '$CHECK'"
	[ "$status" -eq 2 ]
}

@test "empty stdin exits 2 rather than reporting a clean session" {
	run bash -c "printf '' | '$CHECK'"
	[ "$status" -eq 2 ]
}

@test "ANTI-VACUITY: a transcript with no turns exits 0 and says it judged nothing" {
	# A gate that cannot fire must not be indistinguishable from one that found
	# nothing — this repo has been bitten by that twice.
	: >"$T"
	run check
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to judge"* ]]
}

@test "ANTI-VACUITY: the suite's own fired case is reachable" {
	# The counterpart. Every clean case above would also pass against a check that
	# always exits 0; this asserts the firing path is real.
	prompt
	say 'At mise-tasks/stop-guard:1 the wiring is absent.'
	run check
	[ "$status" -eq 1 ]
	[ -n "$output" ]
}
