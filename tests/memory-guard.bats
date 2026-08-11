#!/usr/bin/env bats
# The guard that keeps memory writes going through the tools that enforce their
# own limits.
#
# These tests were `context-budget.bats` until CLOUD-50 moved the budget gate
# into the engine (`batten policy budget`) and deleted the shell task. The budget
# half of that file went with its subject — the equivalent assertions are now
# `crates/batten/tests/cli.rs` and the estimator's in-module unit tests — and the
# guard half moved here, under the name of the task it actually covers.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/memory-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
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
