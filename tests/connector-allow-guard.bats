#!/usr/bin/env bats
# subject: mise-tasks/connector-allow-guard
# CLOUD-191. The `PreToolUse` adapter over `connector-allow-resolve`. The decision
# and its degradations are that file's suite; this one grades the envelope — that
# a verdict reaches the host in the shape the host acts on.
#
# THE DISTINCTION THIS SUITE EXISTS FOR is `allow` versus nothing. Emitting no
# JSON is not a permissive answer, it is an absent one: the ordinary permission
# flow then prompts, which is exactly the failure during a UUID episode. So a row
# that asserts "did not deny" would pass on a guard that decides nothing at all.
# Every row here reads the emitted `permissionDecision` and treats no-output as
# its own third value.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/connector-allow-guard"
	export BATTEN_MCP_CONFIG="$BATS_TEST_TMPDIR/mcp-config.json"
	# A FIXTURE, NOT THE COMMITTED FILE. The guard invokes the resolver with no
	# flags, so without this seam these rows read the repository's real permission
	# rules and break whenever those change — measured: removing six unenforceable
	# grants from `.claude/settings.json` turned the allow row red, and the row was
	# asserting production config rather than the adapter's behaviour.
	export BATTEN_MCP_SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	cat >"$BATTEN_MCP_SETTINGS" <<-'JSON'
		{"permissions":{
		  "allow":["mcp__Claude_Code_Remote__create_session"],
		  "deny":["mcp__Claude_Code_Remote__send_later"]
		}}
	JSON
	cat >"$BATTEN_MCP_CONFIG" <<-'JSON'
		{"mcpServers":{
		  "aaaaaaaa-1111-2222-3333-444444444444":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp"},
		  "bbbbbbbb-5555-6666-7777-888888888888":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta"}
		}}
	JSON
}

# The payload goes through a FILE and the helper prints its path — embedding JSON
# into a `bash -c` string lets the shell reinterpret its braces before the guard
# sees it, the failure `issue-search-guard.bats` records against nine of its rows.
payload() {
	jq -nc --arg t "$1" '{tool_name: $t}' >"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}

decision() {
	run bash -c "'$GUARD' <'$(payload "$1")'"
	[ "$status" -eq 0 ]
	if [ -z "$output" ]; then
		printf 'none\n'
		return 0
	fi
	jq -r '.hookSpecificOutput.permissionDecision' <<<"$output"
}

@test "a committed allow is emitted as an allow under a flipped name" {
	# The suite's spine, and what the declared mutation drops: with the allow arm
	# gone this row goes `none`, which is the approval prompt coming back.
	[ "$(decision mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session)" = allow ]
}

@test "a committed deny is emitted as a deny under a flipped name" {
	[ "$(decision mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)" = deny ]
}

@test "an unstated verb emits nothing, leaving the ordinary flow to decide" {
	[ "$(decision mcp__bbbbbbbb-5555-6666-7777-888888888888__archive_session)" = none ]
}

@test "a claude.ai connector emits nothing" {
	[ "$(decision mcp__aaaaaaaa-1111-2222-3333-444444444444__save_issue)" = none ]
}

@test "a non-MCP tool emits nothing" {
	[ "$(decision Bash)" = none ]
}

@test "the emitted envelope names the PreToolUse event" {
	run bash -c "'$GUARD' <'$(payload mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session)'"
	[ "$status" -eq 0 ]
	[ "$(jq -r '.hookSpecificOutput.hookEventName' <<<"$output")" = PreToolUse ]
}

@test "the reason is pointer-only: it names the alias and the verb, never the live key" {
	run bash -c "'$GUARD' <'$(payload mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)'"
	[ "$status" -eq 0 ]
	reason=$(jq -r '.hookSpecificOutput.permissionDecisionReason' <<<"$output")
	[[ "$reason" == *Claude_Code_Remote* ]]
	[[ "$reason" == *send_later* ]]
	# Non-negotiable 4: the key is the payload here, and must not travel.
	[[ "$reason" != *bbbbbbbb* ]]
}

@test "the bypass gets the guard out of the way entirely" {
	run bash -c "BATTEN_CONNECTOR_ALLOW_BYPASS=1 '$GUARD' <'$(payload mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a payload carrying no tool name emits nothing and exits 0" {
	printf '{}' >"$BATS_TEST_TMPDIR/empty.json"
	run bash -c "'$GUARD' <'$BATS_TEST_TMPDIR/empty.json'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "unreadable stdin exits 0 rather than denying the event" {
	# A non-zero exit is a DENY on this event. A guard that cannot read its input
	# must not take that channel.
	printf 'not json' >"$BATS_TEST_TMPDIR/junk.json"
	run bash -c "'$GUARD' <'$BATS_TEST_TMPDIR/junk.json'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}
