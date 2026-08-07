#!/usr/bin/env bats
# The gate over always-loaded context, and the guard that keeps memories going
# through the tools that enforce their own limits.

setup() {
	BUDGET="$BATS_TEST_DIRNAME/../mise-tasks/context-budget"
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/memory-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

@test "the always-loaded context is within budget today" {
	run "$BUDGET"
	[ "$status" -eq 0 ]
	[[ "$output" == *"AGENTS.md"* ]]
}

@test "an HTML comment costs nothing, because the loader strips it" {
	# The one construct that is already free must not be taxed by the gate.
	local before after
	before=$("$BUDGET" | grep -oE '[0-9]+ chars' | tail -1)
	printf '\n<!-- a maintainer note, stripped before injection, %s -->\n' "$(head -c 400 /dev/zero | tr '\0' 'x')" >>AGENTS.md
	after=$("$BUDGET" | grep -oE '[0-9]+ chars' | tail -1)
	git checkout -- AGENTS.md
	[ "$before" = "$after" ]
}

@test "the line count is reported against the documented 200-line target" {
	run "$BUDGET"
	[[ "$output" == *"lines"* ]]
}

@test "an impossible budget fails, and says what to do about it" {
	BATTEN_CONTEXT_BUDGET=1 run "$BUDGET"
	[ "$status" -eq 1 ]
	[[ "$output" == *"over the 1 budget"* ]]
}

@test "a memory declared always-load counts against the same budget" {
	# The point of the design: moving a section into an always-read memory moves
	# the tokens, it does not remove them.
	mkdir -p .serena/memories/always
	local victim=".serena/memories/always/zz-budget-fixture.md"
	head -c 4000 /dev/zero | tr '\0' 'x' >"$victim"
	run "$BUDGET"
	local out="$output"
	rm -f "$victim"
	rmdir .serena/memories/always 2>/dev/null || true
	[[ "$out" == *"zz-budget-fixture.md"* ]]
}

@test "guard denies a direct write to a memory" {
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\"/x/.serena/memories/github-access.md\"}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	# Names the memory so the redirect is actionable, not just a refusal.
	[[ "$output" == *"github-access"* ]]
}

@test "guard ignores writes outside the memories directory" {
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\"/x/AGENTS.md\"}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "guard fails open on unparseable input and honours the bypass" {
	run bash -c "printf '%s' 'not json' | '$GUARD'"
	[ -z "$output" ]
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\".serena/memories/x.md\"}}' | BATTEN_MEMORY_GUARD_BYPASS=1 '$GUARD'"
	[ -z "$output" ]
}
