#!/usr/bin/env bats
# CLOUD-668. The MCP startup budget is declared and measured, never the host
# default.
#
# The rows are written so that a gate checking only PRESENCE passes the exact
# state the issue was filed about: the host default of 30000 is a declared
# value, and it is the value that lost Serena twice in one session. That is the
# `#MUTANT` this suite is proven against, and it is why `refuses the host
# default` is the load-bearing case rather than `refuses an absent key`.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-timeout-budget"
	S="$BATS_TEST_TMPDIR/settings.json"
}

declare_timeout() { # declare_timeout <value>
	jq -n --arg v "$1" '{env: {MCP_TIMEOUT: $v}, hooks: {}}' >"$S"
}

@test "the committed budget passes" {
	run "$GATE" --settings "$BATS_TEST_DIRNAME/../.claude/settings.json"
	[ "$status" -eq 0 ]
	[[ "$output" == *"at or above the measured floor"* ]]
}

@test "a value below the floor is refused, and both numbers are named" {
	declare_timeout 30000
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"30000"* ]]
	[[ "$output" == *"60000"* ]]
}

@test "exactly the floor passes — the bound is inclusive" {
	declare_timeout 60000
	run "$GATE" --settings "$S"
	[ "$status" -eq 0 ]
}

@test "one millisecond under the floor is refused" {
	declare_timeout 59999
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
}

@test "an absent key is refused — the host default is not a measured budget" {
	jq -n '{hooks: {}}' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"host default"* ]]
}

@test "a non-numeric value is refused rather than compared" {
	declare_timeout "2 minutes"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"whole number of milliseconds"* ]]
}

@test "an unreadable settings file is exit 2, never a silent pass" {
	run "$GATE" --settings "$BATS_TEST_TMPDIR/absent.json"
	[ "$status" -eq 2 ]
}

@test "settings that are not JSON are exit 2, never a silent pass" {
	printf 'not json\n' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 2 ]
}

# Pointer-only (non-negotiable 4): the two numbers, never the settings body.
@test "the refusal echoes no other settings content" {
	jq -n '{env: {MCP_TIMEOUT: "30000", SECRET_TOKEN: "tok-must-not-appear"}}' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" != *"tok-must-not-appear"* ]]
	[[ "$output" != *"SECRET_TOKEN"* ]]
}
