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

# --- predicate 2: a grant that misspells a server that IS here (CLOUD-178) ----
#
# The defect these rows exist for: `.claude/settings.json` granted
# `mcp__Claude_Code_Remote__*` with UNDERSCORES for its whole life while the
# server registers as `Claude-Code-Remote` with HYPHENS, so `create_session`
# prompted on every dispatch and two sessions diagnosed it as the CLOUD-178 UUID
# name-flip instead. Nothing could see it: `mcp-allow-check` reads the settings
# file alone, and the file is self-consistent.
#
# The rows are written so that the OBVIOUS predicate — "a granted server that did
# not register" — fails the cross-host row below. That predicate was written
# first and fired on a legitimate `mcp__claude_ai_Linear__*` entry, which is the
# false-positive rate that gets a gate switched off.

grant() { # grant <rule> [<rule> ...]
	local rules=""
	for r in "$@"; do rules="$rules${rules:+,}\"$r\""; done
	printf '{"enabledMcpjsonServers":[],"permissions":{"allow":[%s]}}\n' "$rules" >"$SETTINGS"
}
attached() { # attached <server>
	local f
	f=$(log_for "$1" 2026-08-11T06-19-12-114Z)
	{
		started
		connected
	} >"$f"
}

@test "a rule misspelling a registered server's separators is refused, and names the real spelling" {
	attached Claude-Code-Remote
	grant "mcp__Claude_Code_Remote__create_session"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Claude_Code_Remote misspelled"* ]]
	[[ "$output" == *"registered as Claude-Code-Remote"* ]]
}

@test "the correctly spelled rule passes" {
	attached Claude-Code-Remote
	grant "mcp__Claude-Code-Remote__create_session"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "case alone is a misspelling too — the match is on the server, not the shape of the typo" {
	attached Linear
	grant "mcp__linear__save_issue"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"registered as Linear"* ]]
}

# THE ROW THAT KILLS THE OBVIOUS PREDICATE. A settings file is shared across
# hosts, and the local-CLI spelling of a connector registers nothing in a web
# session. Absent is not misspelled: nothing here collides with it.
@test "a cross-host rule naming a server that is simply absent is NOT a finding" {
	attached Linear
	grant "mcp__claude_ai_Linear__save_issue" "mcp__Linear__save_issue"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "a deny rule is judged too — a prohibition that names nothing is not in force" {
	attached Claude-Code-Remote
	printf '{"enabledMcpjsonServers":[],"permissions":{"deny":["mcp__Claude_Code_Remote__send_later"]}}\n' >"$SETTINGS"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Claude_Code_Remote misspelled"* ]]
}

@test "one misspelling is reported once, however many rules carry it" {
	attached Claude-Code-Remote
	grant "mcp__Claude_Code_Remote__get_session" \
		"mcp__Claude_Code_Remote__list_sessions" \
		"mcp__Claude_Code_Remote__create_session"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[ "$(grep -c 'misspelled' <<<"$output")" -eq 1 ]
}

# `mcp-allow-check` owns the glob-in-the-server-segment finding. Reporting it
# here as well would make one defect read as two, in two different files.
@test "a glob in the server segment is left to mcp-allow-check" {
	attached Linear
	grant "mcp__*__save_issue"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "a non-MCP permission rule is never judged as a server name" {
	attached Linear
	grant "Bash(git:*)" "mcp__Linear__save_issue"
	run "$GATE" --settings "$SETTINGS" --logs "$LOGS"
	[ "$status" -eq 0 ]
}
