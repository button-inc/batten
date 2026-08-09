#!/usr/bin/env bats
# The gate over MCP allow rules: a permission rule that matches no tool name is
# silent by construction, so the failure it causes (an approval prompt on every
# call) never points back at the settings file that caused it.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-allow-check"
	FIXTURE="$BATS_TEST_TMPDIR/settings.json"
}

# Writes a settings fixture whose permissions.allow is the given JSON array.
allow() {
	printf '{"permissions":{"allow":%s,"deny":[]}}\n' "$1" >"$FIXTURE"
}

# Writes a fixture carrying an enabledMcpjsonServers value alongside the
# allowlist, for the second predicate: an enabled server with no grant.
enabled() {
	printf '{"enabledMcpjsonServers":%s,"permissions":{"allow":%s,"deny":[]}}\n' "$1" "$2" >"$FIXTURE"
}

@test "this repo's own settings pass the gate today" {
	run "$GATE" "$BATS_TEST_DIRNAME/../.claude/settings.json"
	[ "$status" -eq 0 ]
}

@test "a bare server rule with no connector companion passes — that is not this gate's claim" {
	# An earlier version demanded a `mcp__claude_ai_<server>__*` companion. The
	# exposed connector name is chosen per registration by the host (CLOUD-178),
	# so the companion is inert in a web session and the name that would help is
	# an account-specific UUID rule 1 keeps out of committed config. A gate may
	# only assert what it can verify from the repo.
	allow '["mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "both spellings present is also fine" {
	allow '["mcp__Linear", "mcp__claude_ai_Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a connector-only allowlist needs no companion of its own" {
	allow '["mcp__claude_ai_Slack__slack_send_message"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a glob in the server segment is reported, not accepted" {
	allow '["mcp__claude_ai_*__read", "mcp__claude_ai_Linear__*", "mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"server segment cannot be a glob"* ]]
}

@test "a bare unanchored allow glob is reported" {
	allow '["*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"auto-approves nothing"* ]]
}

@test "non-MCP allow rules are none of this gate's business" {
	allow '["Bash(git:*)", "Bash(mise:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "deny rules may glob freely — only allow rules are judged" {
	printf '{"permissions":{"allow":[],"deny":["mcp__*","*"]}}\n' >"$FIXTURE"
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "output is a pointer — it names rules, never settings content at large" {
	allow '["mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[[ "$output" != *'"permissions"'* ]]
}

@test "an enabled server that no allow rule names is reported" {
	# The defect this predicate exists for: serena enabled, nothing granting it,
	# so every memory read prompted and the settings file never pointed at it.
	enabled '["serena"]' '["Bash(git:*)", "mcp__Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no allow rule names it"* ]]
	[[ "$output" == *"serena"* ]]
}

@test "an enabled server granted by a tool-name glob passes" {
	enabled '["serena"]' '["mcp__serena__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "an enabled server granted tool by tool passes" {
	enabled '["serena"]' '["mcp__serena__read_memory", "mcp__serena__list_memories"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a bare server-level rule grants an enabled server" {
	enabled '["serena"]' '["mcp__serena"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "every enabled server needs its own grant, not just one of them" {
	enabled '["serena", "other"]' '["mcp__serena__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"other"* ]]
}

@test "an absent enabledMcpjsonServers leaves the predicate nothing to say" {
	allow '["Bash(git:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "enabledMcpjsonServers set to true is not an enumerable list" {
	# The CLI accepts a boolean there; a gate may only assert what it can read.
	enabled 'true' '["Bash(git:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "unparseable settings exit 2, distinct from a failing allowlist" {
	printf 'not json\n' >"$FIXTURE"
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 2 ]
}

@test "a missing settings file is not a failure this gate invents" {
	run "$GATE" "$BATS_TEST_TMPDIR/absent.json"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to check"* ]]
}
