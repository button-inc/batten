#!/usr/bin/env bats
# mcp-grant-sync (CLOUD-734). The task reads live session state — the generated
# MCP config the host writes per session — so the suite drives it over fixture
# trees, the split tests/mcp-attach-check.bats already uses.
#
# The identifier in every fixture is uuid-shaped and matches no label, which is
# the property the projection exists for: a server is found by the tools it
# exposes, never by what it is called.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/mcp-grant-sync"
	SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	MCPJSON="$BATS_TEST_TMPDIR/mcp.json"
	CONFIG="$BATS_TEST_TMPDIR/mcp-config.json"
	OVERLAY="$BATS_TEST_TMPDIR/settings.local.json"
	SERVER="bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a"
	echo '{"mcpServers":{}}' >"$MCPJSON"
}

run_sync() {
	run "$TASK" --settings "$SETTINGS" --mcp-json "$MCPJSON" --config "$CONFIG" --overlay "$OVERLAY"
}

# A generated config in the shape the host writes: per server a `tools[]`, each
# entry carrying a name and a permission_policy, plus the `headers` block that
# holds the session's credentials and must never reach the report.
config_with() { # config_with <server-id> <tool>...
	local id="$1"
	shift
	local tools="[]"
	for t in "$@"; do
		tools=$(jq -c --arg t "$t" '. + [{name: $t, permission_policy: "always_ask"}]' <<<"$tools")
	done
	jq -n --arg id "$id" --argjson tools "$tools" \
		'{mcpServers: {($id): {type: "http", url: "https://api.example.invalid/v2/ccr-sessions/cse_secret/mcp", headers: {authorization: "Bearer s3cr3t"}, tools: $tools}}}' >"$CONFIG"
}

settings_with() { # settings_with <allow-json> [deny-json]
	jq -n --argjson allow "$1" --argjson deny "${2:-[]}" \
		'{permissions: {allow: $allow, deny: $deny}}' >"$SETTINGS"
}

@test "a committed rule is projected onto the server that exposes its tool" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions create_session
	run_sync
	[ "$status" -eq 0 ]
	run jq -r '.permissions.allow[]' "$OVERLAY"
	[ "$output" = "mcp__${SERVER}__list_sessions" ]
}

# THE WIDENING GUARD, and the case CLOUD-418 requires be shown to fail: the
# server exposes create_session and no committed rule names it, so it must not
# appear. `mise run mutant` drives this red through `grant-sync-widens`.
@test "a tool no committed rule names is never projected" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions create_session
	run_sync
	[ "$status" -eq 0 ]
	# The predicate is over the TOOL SEGMENT of every projected rule: each must
	# be one the committed file named. `create_session` appearing would be the
	# obvious widening; a server-wide `*` is the subtle one, and an assertion
	# that only looked for the tool name by suffix would miss it entirely.
	run bash -c "jq -r '.permissions.allow[] | split(\"__\") | .[2:] | join(\"__\")' '$OVERLAY' | sort -u | tr '\\n' ' '"
	[ "$output" = "list_sessions " ]
}

@test "a committed rule naming a tool the resolved server does not expose exits non-zero" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions","mcp__Claude_Code_Remote__tool_that_went_away"]'
	config_with "$SERVER" list_sessions
	run_sync
	[ "$status" -eq 1 ]
	[[ "$output" == *"name a tool their own resolved server does not expose"* ]]
	# The rule that DOES match is still projected: one stale rule does not
	# forfeit the grants beside it.
	run jq -r '.permissions.allow[]' "$OVERLAY"
	[ "$output" = "mcp__${SERVER}__list_sessions" ]
}

@test "the server is matched by inventory under an identifier matching no label" {
	settings_with '["mcp__Claude_Code_Remote__create_session"]'
	config_with "$SERVER" create_session
	run_sync
	[ "$status" -eq 0 ]
	# Nothing in the fixture spells `Claude_Code_Remote` except the committed
	# rule; the identifier is a uuid, so only the tool name can have found it.
	run jq -r '.permissions.allow[0]' "$OVERLAY"
	[[ "$output" == "mcp__${SERVER}__"* ]]
}

@test "the report carries no tool name, URL or header value" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]' '["mcp__Claude_Code_Remote__create_session"]'
	config_with "$SERVER" list_sessions create_session
	run_sync
	[ "$status" -eq 0 ]
	[[ "$output" != *"list_sessions"* ]]
	[[ "$output" != *"create_session"* ]]
	[[ "$output" != *"http"* ]]
	[[ "$output" != *"s3cr3t"* ]]
	[[ "$output" != *"authorization"* ]]
	# The 8-character prefix the Ready block permits, and no more of the id.
	[[ "$output" == *"bf7c680d"* ]]
	[[ "$output" != *"bf7c680d-5fdc"* ]]
}

@test "a deny is projected too — the direction that otherwise fails open" {
	settings_with '[]' '["mcp__Claude_Code_Remote__send_later"]'
	config_with "$SERVER" send_later
	run_sync
	[ "$status" -eq 0 ]
	run jq -r '.permissions.deny[]' "$OVERLAY"
	[ "$output" = "mcp__${SERVER}__send_later" ]
}

@test "a server this repo declares is skipped — its name is the repo's own" {
	settings_with '["mcp__serena__read_memory"]'
	jq -n '{mcpServers: {serena: {command: "serena"}}}' >"$MCPJSON"
	config_with "$SERVER" read_memory
	run_sync
	[ "$status" -eq 0 ]
	run jq -r '.permissions.allow | length' "$OVERLAY"
	[ "$output" = "0" ]
}

@test "a label already live under its committed name is not copied" {
	settings_with '["mcp__github__create_pull_request"]'
	config_with github create_pull_request
	run_sync
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 label(s) already live"* ]]
	run jq -r '.permissions.allow | length' "$OVERLAY"
	[ "$output" = "0" ]
}

@test "a label whose rules are all globs is unresolved, never guessed at" {
	settings_with '["mcp__Linear__*"]'
	config_with "$SERVER" save_issue get_issue
	run_sync
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 unresolved"* ]]
	run jq -r '.permissions.allow | length' "$OVERLAY"
	[ "$output" = "0" ]
}

@test "re-running converges rather than accumulating, and spares a human's own rules" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions
	jq -n '{permissions: {allow: ["Bash(ls:*)"]}}' >"$OVERLAY"
	run_sync
	[ "$status" -eq 0 ]
	run_sync
	[ "$status" -eq 0 ]
	run jq -r '.permissions.allow | length' "$OVERLAY"
	[ "$output" = "2" ]
	run jq -r '[.permissions.allow[] | select(. == "Bash(ls:*)")] | length' "$OVERLAY"
	[ "$output" = "1" ]
}

# The previous run's output is identified by SHAPE, so a rule for a server that
# is no longer attached is dropped rather than left behind granting something
# the committed file no longer projects anywhere.
@test "a stale projection from an earlier registration is replaced, not kept" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions
	jq -n '{permissions: {allow: ["mcp__4db58e41-cd4e-4818-8922-46cf616593f4__list_sessions"]}}' >"$OVERLAY"
	run_sync
	[ "$status" -eq 0 ]
	run jq -r '.permissions.allow[]' "$OVERLAY"
	[ "$output" = "mcp__${SERVER}__list_sessions" ]
}

@test "no generated config means no live session, and nothing is written" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	run "$TASK" --settings "$SETTINGS" --mcp-json "$MCPJSON" --config "$BATS_TEST_TMPDIR/absent.json" --overlay "$OVERLAY"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not a live session"* ]]
	[ ! -f "$OVERLAY" ]
}

@test "an unreadable overlay is refused rather than overwritten" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions
	printf 'not json at all' >"$OVERLAY"
	run_sync
	[ "$status" -eq 2 ]
	run cat "$OVERLAY"
	[ "$output" = "not json at all" ]
}

@test "--dry-run computes the projection and writes nothing" {
	settings_with '["mcp__Claude_Code_Remote__list_sessions"]'
	config_with "$SERVER" list_sessions
	run "$TASK" --settings "$SETTINGS" --mcp-json "$MCPJSON" --config "$CONFIG" --overlay "$OVERLAY" --dry-run
	[ "$status" -eq 0 ]
	[[ "$output" == *"projected 1 allow"* ]]
	[ ! -f "$OVERLAY" ]
}
