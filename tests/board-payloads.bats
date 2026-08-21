#!/usr/bin/env bats
# subject: mise-tasks/board-payloads
#
# CLOUD-782. Every case drives a FIXTURE transcript, never the live one. A case
# reading the real session would pass for the wrong reason and could never fail:
# the host produces exactly one transcript, so the suite would ship as coverage
# while exercising a single row (CLOUD-418), which is the shape
# `transcript-corpus-check` records for its own root.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/board-payloads"
	T="$BATS_TEST_TMPDIR/transcript.jsonl"
	OUT="$BATS_TEST_TMPDIR/out-$BATS_TEST_NUMBER"
	export BATTEN_TRANSCRIPT_FILE="$T"
	export BOARD_PAYLOADS_DIR="$OUT"
	: >"$T"
	N=0
}

# call <tool-name> <payload-json> — one tool_use/tool_result pair, joined by id,
# in the shape the host writes. The pair is what carries the tool name; the
# payload alone never does, which is the whole point of the gate.
call() {
	N=$((N + 1))
	local id="tu$N" name="$1" payload="$2"
	jq -cn --arg id "$id" --arg name "$name" \
		'{type:"assistant",message:{content:[{type:"tool_use",id:$id,name:$name}]}}' >>"$T"
	jq -cn --arg id "$id" --arg p "$payload" \
		'{type:"user",message:{content:[{type:"tool_result",tool_use_id:$id,content:[{type:"text",text:$p}]}]}}' >>"$T"
}

@test "a get_issue payload is recovered" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 0 ]
	[ "$(jq -r .status "$OUT/CLOUD-9.json")" = "Todo" ]
}

# THE DISCRIMINATING CASE. A save_issue response is shape-identical across id,
# status and attachments and omits only `relations`, so a field-presence
# discriminator prefers this later, poorer payload — measured three times in one
# session before the rule was found.
@test "CLOUD-782: a LATER save_issue response does not displace the get_issue payload" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	call mcp__Linear__save_issue '{"id":"CLOUD-9","status":"In Progress","attachments":[]}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 0 ]
	[ "$(jq -r .status "$OUT/CLOUD-9.json")" = "Todo" ]
	[ "$(jq -r 'has("relations")' "$OUT/CLOUD-9.json")" = "true" ]
}

@test "CLOUD-782: newest wins among two get_issue payloads — the compaction case" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Backlog","attachments":[],"relations":{"blockedBy":[]}}'
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 0 ]
	[ "$(jq -r .status "$OUT/CLOUD-9.json")" = "Todo" ]
}

# The MCP server reconnects under a different alias mid-session (CLOUD-178), so
# the same call arrives under two names. A full-name match harvests nothing after
# a reconnect and reports success doing it.
@test "CLOUD-782: a reconnected server alias still matches on the suffix" {
	call mcp__4db58e41-cd4e-4818-8922-46cf616593f4__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 0 ]
	[ "$(jq -r .status "$OUT/CLOUD-9.json")" = "Todo" ]
}

@test "CLOUD-782: an id present only in a save_issue response is not recovered" {
	call mcp__Linear__save_issue '{"id":"CLOUD-9","status":"Done","attachments":[]}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-9"* ]]
}

@test "several ids are recovered in one run" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	call mcp__Linear__get_issue '{"id":"CLOUD-10","status":"Done","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9 CLOUD-10
	[ "$status" -eq 0 ]
	[[ "$output" == *"recovered 2 of 2"* ]]
}

@test "an id absent from the transcript is exit 1 and named" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9 CLOUD-404
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-404"* ]]
	[[ "$output" != *"CLOUD-9 "* ]]
}

@test "an unreadable transcript is exit 2, never an empty harvest" {
	BATTEN_TRANSCRIPT_FILE="$BATS_TEST_TMPDIR/absent.jsonl" run "$TASK" CLOUD-9
	[ "$status" -eq 2 ]
	[[ "$output" == *"not an empty harvest"* ]]
}

@test "a malformed id is a caller bug" {
	run "$TASK" not-an-id
	[ "$status" -eq 2 ]
}

@test "no arguments is a caller bug" {
	run "$TASK"
	[ "$status" -eq 2 ]
}

# Rule 4: the transcript is the richest secret surface the engine can be pointed
# at, so the report carries counts and ids and nothing of a body.
@test "the report carries no substring of any payload body" {
	call mcp__Linear__get_issue '{"id":"CLOUD-9","status":"Todo","description":"customer detail here","attachments":[],"relations":{"blockedBy":[]}}'
	run "$TASK" CLOUD-9
	[ "$status" -eq 0 ]
	[[ "$output" != *"customer detail"* ]]
}
