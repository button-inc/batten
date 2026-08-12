#!/usr/bin/env bats
# CLOUD-451. The hook adapter's decision table: which tool calls are handoffs,
# and what happens to one when nothing is holding the container open.
#
# The guard's own predicate is `plan-hold-check`, covered in tests/plan-hold.bats.
# What is proved here is the adapter: the matcher, the deny channel, the bypass,
# and — the half that matters most for a guard on this path — that every shape it
# cannot understand is ALLOWED. A jammed guard here would leave a session unable
# to ask a human for help.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-guard"
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	cd "$REPO" || return 1
}

teardown() {
	[ -n "${HELD_PID:-}" ] && kill "$HELD_PID" 2>/dev/null
	return 0
}

# The adapter, driven the way the harness drives it.
event() { jq -nc --arg t "$1" '{tool_name: $t, tool_input: {}}' | "$GUARD"; }

# Arm a hold without running the sleeper: the adapter's subject is the verdict,
# not the process, and a real `plan-hold` would make every case here wait.
hold() {
	local dir
	dir=$("$CHECK" dir)
	mkdir -p "$dir"
	sleep 30 &
	HELD_PID=$!
	printf '%s\n' "$HELD_PID" >"$dir/$HELD_PID"
}

denied() { [[ "$1" == *'"permissionDecision": "deny"'* ]]; }

# --- the matcher ---------------------------------------------------------------

@test "ExitPlanMode with no hold is denied" {
	run event ExitPlanMode
	[ "$status" -eq 0 ]
	denied "$output"
	# The refusal names the command that fixes it — a deny with no fix is the
	# shape this repo's refusal type exists to forbid.
	[[ "$output" == *"mise run plan-hold"* ]]
}

@test "AskUserQuestion with no hold is denied on the same predicate" {
	run event AskUserQuestion
	[ "$status" -eq 0 ]
	denied "$output"
}

@test "the same call is allowed the moment a hold is live" {
	hold
	run event ExitPlanMode
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "no other tool is judged — the matcher is those two and nothing else" {
	for tool in Bash Write Edit Read Task ExitPlanModeSomething AskUser ""; do
		run event "$tool"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

# --- fail open -----------------------------------------------------------------

@test "unparseable stdin allows" {
	run bash -c "printf 'not json at all' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "empty stdin allows" {
	run bash -c "printf '' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a payload with no tool_name allows" {
	run bash -c "printf '%s' '{\"tool_input\":{}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an unreadable predicate allows rather than denying — exit 2 is not a verdict" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" bash -c "printf '%s' '{\"tool_name\":\"ExitPlanMode\"}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass is honoured, so ending a turn idle stays deliberately possible" {
	run env BATTEN_PLAN_HOLD_BYPASS=1 bash -c "printf '%s' '{\"tool_name\":\"ExitPlanMode\"}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- output contract ------------------------------------------------------------

@test "the deny is pointer-only and byte-stable across runs" {
	run event ExitPlanMode
	local first="$output"
	run event ExitPlanMode
	[ "$output" = "$first" ]
	# Valid JSON on the channel the harness reads.
	printf '%s' "$first" | jq -e '.hookSpecificOutput.permissionDecision == "deny"'
}
