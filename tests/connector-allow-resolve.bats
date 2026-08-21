#!/usr/bin/env bats
# subject: mise-tasks/connector-allow-resolve.sh
# CLOUD-191. The resolver that applies the COMMITTED permissions to whichever
# server name the host exposed, by looking the live key up in the injected config
# and comparing its `mcp_url` endpoint against one committed public address.
#
# THE SPINE OF THIS SUITE IS THE PAIR OF ARMS UNDER A FLIPPED NAME. Two things
# break during a UUID episode and only one of them is visible: an allow that
# under-matches costs an approval prompt a human sees, while a deny that
# under-matches reads as a prohibition and enforces NOTHING. AGENTS.md's ban on
# babysitting timers rests on the second, so `send_later` under a flipped name is
# the row that matters most here, not `create_session`.
#
# THE SECOND SPINE IS THE CONNECTOR ROW. A claude.ai connector is governed by the
# connector layer, not by `permissions.allow` — which is why Linear kept working
# through both naming episodes under a name no committed rule spells. Translating
# its name would GRANT something the committed file does not state, so it must
# resolve to silence. A resolver that "helpfully" allowed it would be widening
# policy, which is the one thing this must never do.
#
# EVERY KEY IN THESE FIXTURES IS SYNTHETIC. The endpoints are the real public
# vendor addresses, because those are the committable half; the keys beside them
# are invented, because a real one is account-specific (rule 1). The last row
# asserts that property over the resolver's own source.

setup() {
	RESOLVE="$BATS_TEST_DIRNAME/../mise-tasks/connector-allow-resolve.sh"
	CFG="$BATS_TEST_TMPDIR/mcp-config.json"
	SETTINGS="$BATS_TEST_TMPDIR/settings.json"

	# Two proxied servers and one that is not proxied at all. `github` carries no
	# `mcp_url`, which is the shape that must not be mistaken for an unresolvable
	# connector — it is simply not one.
	cat >"$CFG" <<-'JSON'
		{"mcpServers":{
		  "github":{"url":"https://api.anthropic.com/v1/code/mcp/github"},
		  "aaaaaaaa-1111-2222-3333-444444444444":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp"},
		  "bbbbbbbb-5555-6666-7777-888888888888":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta&session=x"}
		}}
	JSON

	# A miniature of the committed file: one exact allow, one deny, and nothing
	# said about a third verb.
	cat >"$SETTINGS" <<-'JSON'
		{"permissions":{
		  "allow":["mcp__Claude_Code_Remote__create_session","mcp__Linear__save_issue"],
		  "deny":["mcp__Claude_Code_Remote__send_later"]
		}}
	JSON
}

verdict() { # verdict <tool-name>
	run "$RESOLVE" "$1" --config "$CFG" --settings "$SETTINGS"
	[ "$status" -eq 0 ]
	printf '%s\n' "$output"
}

# --- the toolbox server, exposed under a name no committed rule spells --------

@test "a committed allow reaches the toolbox server under a flipped name" {
	[ "$(verdict mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session)" = "allow Claude_Code_Remote" ]
}

@test "a committed deny reaches the toolbox server under a flipped name" {
	# The load-bearing row. Under-matching here is silent: the prohibition reads
	# as present and enforces nothing.
	[ "$(verdict mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)" = "deny Claude_Code_Remote" ]
}

@test "a verb the committed file says nothing about resolves to silence" {
	# Silence is not allow: it hands the call back to the ordinary permission
	# flow, so an unstated verb behaves exactly as it does today.
	[ "$(verdict mcp__bbbbbbbb-5555-6666-7777-888888888888__archive_session)" = "silence Claude_Code_Remote" ]
}

@test "a deny outranks an allow glob over the same server" {
	# The declared mutation reverses this ordering. A rule set that allows the
	# whole server and denies one verb under it must deny — otherwise
	# `mcp__Claude_Code_Remote__*` pre-approves the timers AGENTS.md bans.
	cat >"$SETTINGS" <<-'JSON'
		{"permissions":{
		  "allow":["mcp__Claude_Code_Remote__*"],
		  "deny":["mcp__Claude_Code_Remote__send_later"]
		}}
	JSON
	[ "$(verdict mcp__bbbbbbbb-5555-6666-7777-888888888888__send_later)" = "deny Claude_Code_Remote" ]
	# …and the glob still grants everything it should.
	[ "$(verdict mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session)" = "allow Claude_Code_Remote" ]
}

# --- what must NOT be translated ----------------------------------------------

@test "a claude.ai connector resolves to silence, never to a grant" {
	# Governed by the connector layer. The settings file allows
	# `mcp__Linear__save_issue`, and translating the flipped name onto it would
	# grant what the committed file does not actually govern.
	[ "$(verdict mcp__aaaaaaaa-1111-2222-3333-444444444444__save_issue)" = "silence -" ]
}

@test "a server carrying no mcp_url resolves to silence" {
	[ "$(verdict mcp__github__search_code)" = "silence -" ]
}

@test "the readable spelling is left to the CLI's own matching" {
	# Nothing to translate: the committed rule matches natively, and answering
	# here would put this resolver in the path of every call it has nothing to
	# say about.
	[ "$(verdict mcp__Claude_Code_Remote__create_session)" = "silence Claude_Code_Remote" ]
}

@test "a non-MCP tool resolves to silence" {
	[ "$(verdict Bash)" = "silence -" ]
}

# --- degradations: every one of them must reach silence, never a grant --------

@test "an absent injected config resolves to silence" {
	run "$RESOLVE" mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session \
		--config "$BATS_TEST_TMPDIR/nope.json" --settings "$SETTINGS"
	[ "$status" -eq 0 ]
	[ "$output" = "silence -" ]
}

@test "an absent settings file resolves to silence" {
	run "$RESOLVE" mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session \
		--config "$CFG" --settings "$BATS_TEST_TMPDIR/nope.json"
	[ "$status" -eq 0 ]
	[ "$output" = "silence -" ]
}

@test "an unparseable injected config resolves to silence" {
	printf 'not json' >"$BATS_TEST_TMPDIR/bad.json"
	run "$RESOLVE" mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session \
		--config "$BATS_TEST_TMPDIR/bad.json" --settings "$SETTINGS"
	[ "$status" -eq 0 ]
	[ "$output" = "silence -" ]
}

@test "a server segment carrying jq metacharacters cannot reach the query" {
	# The segment is host-chosen text. It is passed with `--arg`, never spliced,
	# so this is a lookup miss rather than a parse error or an injection.
	run "$RESOLVE" 'mcp__" or true or "__create_session' --config "$CFG" --settings "$SETTINGS"
	[ "$status" -eq 0 ]
	[ "$output" = "silence -" ]
}

# --- rule 1 --------------------------------------------------------------------

@test "no account-specific identifier appears in the resolver's source" {
	# The one thing this file exists to handle is the one thing it must never
	# carry. A UUID shape anywhere in the source means somebody committed an
	# account fact instead of deriving it.
	run grep -nEi '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$RESOLVE"
	[ "$status" -ne 0 ]
}
