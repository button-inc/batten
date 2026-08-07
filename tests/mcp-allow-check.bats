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

@test "this repo's own settings pass the gate today" {
	run "$GATE" "$BATS_TEST_DIRNAME/../.claude/settings.json"
	[ "$status" -eq 0 ]
}

@test "the shipped bug: a local server rule with no connector companion is caught" {
	allow '["mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mcp__claude_ai_Linear__*"* ]]
}

@test "the wildcard spelling of the same one-sided rule is caught too" {
	allow '["mcp__Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"claude_ai_Linear"* ]]
}

@test "both spellings present is the passing state" {
	allow '["mcp__Linear", "mcp__claude_ai_Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "casing is preserved — a lowercase companion does not cover a capitalised server" {
	allow '["mcp__Linear", "mcp__claude_ai_linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
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
