#!/usr/bin/env bats
# mcp-attach-check (CLOUD-316). The gate reads live CLI session logs, so the
# suite drives it over fixture log trees — the split gh-guard/gh-guard-check
# already uses. Every record shape below is copied from a real log written by
# this repo's own session on 2026-08-11, including the two shapes that look like
# the signature and are not.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-attach-check"
	SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	LOGS="$BATS_TEST_TMPDIR/logs"
	mkdir -p "$LOGS"
	echo '{"enabledMcpjsonServers":["serena"]}' >"$SETTINGS"
}

log_for() { # log_for <server> <file-stamp>
	mkdir -p "$LOGS/mcp-logs-$1"
	printf '%s\n' "$LOGS/mcp-logs-$1/$2.jsonl"
}

started() {
	echo '{"debug":"Starting connection with timeout of 30000ms","timestamp":"2026-08-11T06:19:12.814Z"}'
}
connected() {
	echo '{"debug":"Successfully connected (transport: stdio) in 12495ms","timestamp":"2026-08-11T06:19:25.302Z"}'
}
# Routine startup chatter, tee'd into records with an `error` KEY on a perfectly
# healthy launch. A gate keyed on has("error") would fail every green session.
stderr_noise() {
	echo '{"error":"Server stderr: INFO 2026-08-11 06:19:23,467 serena.agent:__init__:631 - Starting Serena server (version=1.6.1)","timestamp":"2026-08-11T06:19:23.467Z"}'
}

@test "a clean log passes" {
	f=$(log_for serena 2026-08-11T06-19-12-114Z)
	{
		started
		stderr_noise
		connected
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
	[[ "$output" == *"attached this session"* ]]
}

# The shape CLOUD-316 was written from: the exec died.
@test "a -32000 failure fails and names the server and the code" {
	f=$(log_for serena 2026-08-11T04-17-22-000Z)
	{
		started
		echo '{"debug":"Connection failed after 29999ms (-32000): MCP error -32000: Connection closed","timestamp":"2026-08-11T04:17:52.696Z"}'
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"serena -32000"* ]]
}

# The very next real occurrence, and NOT -32000: the exec was merely too slow.
# Keying the predicate on the literal code would have passed this green.
@test "a CONNECT_TIMEOUT failure fails too — the code is not fixed at -32000" {
	f=$(log_for serena 2026-08-11T05-41-40-873Z)
	{
		started
		echo '{"debug":"Connection timeout triggered after 30016ms (limit: 30000ms)","timestamp":"2026-08-11T05:42:11.316Z"}'
		echo '{"debug":"Connection failed after 30019ms (CONNECT_TIMEOUT): MCP server \"serena\" connection timed out after 30000ms","timestamp":"2026-08-11T05:42:11.321Z"}'
		echo '{"error":"Connection failed (CONNECT_TIMEOUT): MCP server \"serena\" connection timed out after 30000ms","timestamp":"2026-08-11T05:42:11.321Z"}'
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"serena CONNECT_TIMEOUT"* ]]
}

@test "a failure followed by a successful reconnect passes — the LAST outcome decides" {
	f=$(log_for serena 2026-08-11T05-52-50-396Z)
	{
		started
		echo '{"debug":"Connection failed after 30019ms (CONNECT_TIMEOUT): timed out","timestamp":"2026-08-11T05:52:51.000Z"}'
		started
		connected
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

# Ordering is by the log's ISO-8601 NAME, whose lexicographic order is its
# chronological order. The mtimes here are set deliberately AGAINST the name
# order, so a regression to mtime ordering fails this test rather than passing
# by coincidence.
@test "only the NEWEST log is judged — a stale failure does not condemn a good session" {
	old=$(log_for serena 2026-08-07T05-04-29-250Z)
	{
		started
		echo '{"debug":"Connection failed after 100ms (-32000): Connection closed","timestamp":"2026-08-07T05:04:29.250Z"}'
	} >"$old"
	new=$(log_for serena 2026-08-11T06-19-12-114Z)
	{
		started
		connected
	} >"$new"
	# Inverted on purpose: the STALE log is the most recently written file.
	touch -d '2026-08-11 07:00:00' "$old"
	touch -d '2026-08-07 05:04:29' "$new"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "an enabled server with no log directory at all fails" {
	mkdir -p "$LOGS/mcp-logs-github"
	{
		started
		connected
	} >"$LOGS/mcp-logs-github/x.jsonl"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"serena no-log"* ]]
}

@test "a log with no connection outcome at all fails rather than passing silently" {
	f=$(log_for serena 2026-08-11T06-00-00-000Z)
	{
		started
		stderr_noise
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"serena no-outcome"* ]]
}

# Fails open, and ONLY here: no root means this is not a live CLI session (CI, a
# bare checkout, another harness). A gate that cannot look must not return a
# verdict it did not compute.
@test "a missing log root is not a live session — fail open" {
	run "$GATE" --settings "$SETTINGS" --logs "$BATS_TEST_TMPDIR/absent"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not a live session"* ]]
}

@test "no enabled servers is nothing to check" {
	echo '{"enabledMcpjsonServers":[]}' >"$SETTINGS"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "an unreadable settings file is exit 2, never a clean pass" {
	echo 'not json' >"$SETTINGS"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 2 ]
}

@test "every enabled server is judged, not just the first" {
	echo '{"enabledMcpjsonServers":["serena","github"]}' >"$SETTINGS"
	f=$(log_for serena 2026-08-11T06-19-12-114Z)
	{
		started
		connected
	} >"$f"
	g=$(log_for github 2026-08-11T06-19-12-114Z)
	{
		started
		echo '{"debug":"Connection failed after 10ms (-32000): Connection closed","timestamp":"2026-08-11T06:19:12.900Z"}'
	} >"$g"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"github -32000"* ]]
}

# --- did the client actually spawn it? (CLOUD-714) ---------------------------
#
# The three 2026-08-19 failures each burned ~28,300 ms and left no trace at all —
# no serena log, no `Server stderr:` record. That signature has two very different
# causes and the logs cannot separate them, so the shim's ledger is what makes the
# distinction a file read. These rows pin it in all three directions, because
# "no entry" is only evidence when the shim is wired.

timed_out() { # a real CONNECT_TIMEOUT record, copied from 2026-08-19
	echo '{"debug":"Connection failed after 28476ms (CONNECT_TIMEOUT): MCP server \"serena\" connection timed out after 30000ms","timestamp":"2026-08-19T07:05:45.000Z"}'
}
# The log NAME is the attempt's UTC start, which is the instant a spawn is matched
# against — the same key the gate already sorts on, so no second notion of "when".
attempt() { # attempt <file-stamp> -> epoch of that stamp
	date -u -d "$(printf '%s' "$1" | sed -E 's/^(.{10})T(..)-(..)-(..)-.*Z$/\1T\2:\3:\4Z/')" +%s
}

@test "a timeout WITH a matching spawn record reads as spawned-and-unresponsive" {
	stamp=2026-08-19T07-05-16-328Z
	f=$(log_for serena "$stamp")
	{
		started
		timed_out
	} >"$f"
	printf '%s\tserena\t4543\t2.10\t3\n' "$(attempt "$stamp")" >"$BATS_TEST_TMPDIR/spawns"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/spawns"
	[ "$status" -eq 1 ]
	[[ "$output" == *"serena CONNECT_TIMEOUT"* ]]
	[[ "$output" == *"the shim recorded the launch"* ]]
}

@test "a timeout with NO spawn record for that attempt reads as never-spawned" {
	# The ledger carries an older serena launch, which is what licenses the
	# verdict: the shim is demonstrably wired for this server, so its silence
	# about THIS attempt means something.
	stamp=2026-08-19T14-30-14-698Z
	f=$(log_for serena "$stamp")
	{
		started
		timed_out
	} >"$f"
	printf '%s\tserena\t4543\t0.30\t0\n' "$(($(attempt "$stamp") - 26000))" >"$BATS_TEST_TMPDIR/spawns"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/spawns"
	[ "$status" -eq 1 ]
	[[ "$output" == *"never-spawned"* ]]
	[[ "$output" == *"recorded none for this attempt"* ]]
}

@test "A TIMEOUT WITH NO LEDGER AT ALL IS UNRECORDED, NEVER never-spawned" {
	# The boundary that keeps this from becoming a verdict computed out of
	# nothing. A server launched directly, or a clone whose $GIT_DIR was cleaned,
	# has no entries for an innocent reason.
	f=$(log_for serena 2026-08-19T07-41-58-210Z)
	{
		started
		timed_out
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/absent"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unrecorded"* ]]
	[[ "$output" != *"never-spawned"* ]]
}

@test "a ledger that has never seen this server is unrecorded, not never-spawned" {
	f=$(log_for serena 2026-08-19T07-41-58-210Z)
	{
		started
		timed_out
	} >"$f"
	printf '%s\tgithub\t99\t0.10\t0\n' "$(date +%s)" >"$BATS_TEST_TMPDIR/spawns"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/spawns"
	[ "$status" -eq 1 ]
	[[ "$output" == *"the shim is not wired for it"* ]]
}

@test "a healthy attach is unaffected by the ledger in either state" {
	f=$(log_for serena 2026-08-19T15-04-19-000Z)
	{
		started
		connected
	} >"$f"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/absent"
	[ "$status" -eq 0 ]
	printf '%s\tserena\t1\t0.10\t0\n' "$(date +%s)" >"$BATS_TEST_TMPDIR/spawns"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/spawns"
	[ "$status" -eq 0 ]
	[[ "$output" == *"attached this session"* ]]
}

@test "the exit contract is unchanged — only the pointer detail is added" {
	f=$(log_for serena 2026-08-19T07-05-16-328Z)
	{
		started
		timed_out
	} >"$f"
	printf '%s\tserena\t1\t0.10\t0\n' "$(date +%s)" >"$BATS_TEST_TMPDIR/spawns"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS" --spawns "$BATS_TEST_TMPDIR/spawns"
	[ "$status" -eq 1 ]
	# Pointer-only per non-negotiable 4: the verdict names a state, never a log
	# line, and the server's stderr is content this repo does not control.
	[[ "$output" != *"Server stderr"* ]]
	[[ "$output" != *"connection timed out after"* ]]
}
