#!/usr/bin/env bats
# The SessionStart hook's load-bearing properties (CLOUD-196). The hook's effect
# — a provisioned toolchain — is not assertable in a unit test, so these pin the
# two properties whose loss would silently restore the defect: that it is
# synchronous, and that it fails loudly rather than exiting 0 on a broken setup.

setup() {
	HOOK="$BATS_TEST_DIRNAME/../.claude/hooks/session-start.sh"
	SETTINGS="$BATS_TEST_DIRNAME/../.claude/settings.json"
}

@test "the hook is executable" {
	[ -x "$HOOK" ]
}

@test "the hook is synchronous — async would restore the race it closes" {
	# `{"async": true}` on stdout tells the client to start the session while
	# this still runs, which is exactly the window the MCP handshake lost. The
	# property is what the hook EMITS, not whether the word appears — the
	# rationale comment names async precisely to explain why it is absent, and
	# an earlier version of this test failed on that comment.
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"async"* ]]

	# Belt and braces: no executable (non-comment) line declares it either.
	run bash -c "grep -v '^[[:space:]]*#' '$HOOK' | grep -c '\"async\"' || true"
	[ "$output" -eq 0 ]
}

@test "mise install runs — the step whose absence was the defect" {
	# `mise exec` in .mcp.json installs on demand; this is what makes that a
	# pure exec instead of a 24-second install inside the MCP startup window.
	run grep -q "mise install" "$HOOK"
	[ "$status" -eq 0 ]
}

@test "a failed step exits non-zero — absence must never be silent" {
	run grep -q "exit 1" "$HOOK"
	[ "$status" -eq 0 ]
}

@test "the hook is registered as a SessionStart hook" {
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
hooks = d['hooks']['SessionStart']
cmds = [h['command'] for g in hooks for h in g['hooks']]
assert any('session-start.sh' in c for c in cmds), cmds
print('registered')
"
	[ "$status" -eq 0 ]
	[[ "$output" == *"registered"* ]]
}

@test "the hook runs green on this checkout" {
	# Idempotent by construction, so running it here is safe and is the only
	# end-to-end assertion available: the steps are all already satisfied.
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"toolchain provisioned"* ]]
}
