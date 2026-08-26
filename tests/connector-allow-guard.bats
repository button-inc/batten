#!/usr/bin/env bats
# subject: mise-tasks/connector-allow-guard.sh
# CLOUD-191. The `PreToolUse` adapter over `connector-allow-resolve`. The decision
# and its degradations are that file's suite; this one grades the envelope — that
# a verdict reaches the host in the shape the host acts on.
#
# THE DISTINCTION THIS SUITE EXISTS FOR is `allow` versus nothing. Saying
# nothing is not a permissive answer, it is an absent one: the ordinary
# permission flow then prompts, which is exactly the failure during a UUID
# episode. So a row that asserts "did not deny" would pass on a guard that
# decides nothing at all. Every row here reads the guard's answer and treats
# silence as its own third value.
#
# THE ANSWER IS READ UNDER THE HANDLER CONTRACT, not out of a host document, and
# that is the correction this suite carries. The guard is dispatched by `batten
# hook` (CLOUD-312 row 5), where a `hookSpecificOutput` object on stdout is
# `Violation::ImpersonatedHost` — reported and dropped. Reading the document was
# how the suite stayed green over a guard whose every verdict the door was
# discarding: measured 2026-08-26 on the live wiring. So a refusal is exit 2 with
# its reason on stderr, an allow is advisory text on stdout, and silence is
# exit 0 with neither.
#
# `tests/connector-allow-door.bats` is the second tier over the compiled binary,
# and it is the one that would have caught this: a `with input as` style row —
# and this file's `run <the script>` is the bash equivalent — fabricates the very
# shape the engine may be unable to consume.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/connector-allow-guard.sh"
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

# The three answers a handler can give, read the way the door reads them. stderr
# is kept SEPARATE from stdout — bats merges them into `$output` by default, and
# a merged stream cannot tell a refusal's reason from an advisory.
decision() {
	run bash -c "'$GUARD' <'$(payload "$1")' >'$BATS_TEST_TMPDIR/out' 2>'$BATS_TEST_TMPDIR/err'"
	REASON_OUT=$(cat "$BATS_TEST_TMPDIR/out")
	REASON_ERR=$(cat "$BATS_TEST_TMPDIR/err")
	if [ "$status" -eq 2 ] && [ -n "$REASON_ERR" ]; then
		printf 'deny\n'
		return 0
	fi
	[ "$status" -eq 0 ]
	if [ -z "$REASON_OUT" ]; then
		printf 'none\n'
		return 0
	fi
	# Non-negotiable: an advisory must not BE a host document, or the door drops
	# it. Asserted here rather than only in the door suite, because this is the
	# shape every migrated handler gets wrong the same way.
	[[ "$REASON_OUT" != *hookSpecificOutput* ]]
	[[ "$REASON_OUT" != *permissionDecision* ]]
	printf 'allow\n'
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
	# WHAT THIS ROW ASSERTS CHANGED WITH THE CHANNEL, and the row is kept rather
	# than deleted because the property behind it survives: the guard must not
	# name a host's event spelling AT ALL now. Naming `PreToolUse` was correct
	# while it wrote the host's document and is the impersonation the door drops
	# now that it does not. Same question — is the envelope right for where this
	# answer goes — with the right answer for where it goes today.
	run bash -c "'$GUARD' <'$(payload mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session)' 2>/dev/null"
	[ "$status" -eq 0 ]
	[ -n "$output" ]
	[[ "$output" != *PreToolUse* ]]
	[[ "$output" != *hookEventName* ]]
}

@test "the reason is pointer-only: it names the alias and the verb, never the live key" {
	run bash -c "'$GUARD' <'$(payload mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)' 2>&1 >/dev/null"
	[ "$status" -eq 2 ]
	reason="$output"
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
