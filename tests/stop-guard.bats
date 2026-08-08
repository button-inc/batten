#!/usr/bin/env bats
# The Stop hook body: one bounded re-prompt per turn, and fail-open everywhere
# else. CLOUD-187 is why this suite carries the wiring assertion too — a hook that
# lands mid-session is not in that session's wiring, so the suite is the only
# in-session proof that the entry exists at all.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/stop-guard"
	SETTINGS="$BATS_TEST_DIRNAME/../.claude/settings.json"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# The real payload shape, captured from two live Stop invocations: 11 keys, of
# which this guard reads exactly two.
stop() {
	jq -nc --arg m "$1" --argjson active "${2:-false}" \
		'{hook_event_name: "Stop", session_id: "s", cwd: ".",
		  transcript_path: "/nonexistent.jsonl",
		  stop_hook_active: $active, last_assistant_message: $m}' | "$GUARD"
}

kicked() {
	[[ "$1" == *'"additionalContext"'* ]]
}

@test "a turn whose final message carries the tell is kicked" {
	run stop 'The rebase is clean. Worth noting that the lock file still drifts.'
	kicked "$output"
	[ "$status" -eq 0 ]
}

@test "the kick names the rule and the durable destination" {
	run stop 'Worth noting the receipt is stale.'
	[[ "$output" == *"hedged-flag-framing"* ]]
	[[ "$output" == *"CLOUD-"* ]]
}

@test "the kick declares the Stop event, so the harness routes it as feedback" {
	run stop 'Worth noting one thing.'
	[[ "$output" == *'"hookEventName"'* ]]
	[[ "$output" == *'"Stop"'* ]]
}

@test "the kick is valid JSON on stdout" {
	run bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Worth noting the drift.\"}' | $GUARD | jq -e .hookSpecificOutput.additionalContext"
	[ "$status" -eq 0 ]
}

# --- exactly once ------------------------------------------------------------

@test "the re-entry caused by a previous kick is not kicked again" {
	# This is the whole of "exactly once": no state file, no cursor. The same
	# message that fires on the first Stop must be silent when the harness reports
	# it is already continuing because of one.
	run stop 'Worth noting the receipt is stale.' true
	! kicked "$output"
	[ -z "$output" ]
	[ "$status" -eq 0 ]
}

@test "the recursion bound survives a garbage stop_hook_active rather than proceeding" {
	# The inverse spelling (`!= "true"` then proceed) runs the predicate on
	# unparseable input, which defeats the bound down to the harness cap of 8.
	run bash -c "printf 'not json at all' | $GUARD"
	! kicked "$output"
	[ "$status" -eq 0 ]
}

# --- failure posture ---------------------------------------------------------

@test "a clean final message is silent" {
	run stop 'Landed on main by fast-forward, CI green.'
	! kicked "$output"
	[ -z "$output" ]
	[ "$status" -eq 0 ]
}

@test "an absent last_assistant_message fails open" {
	run bash -c "jq -nc '{stop_hook_active:false}' | $GUARD"
	! kicked "$output"
	[ "$status" -eq 0 ]
}

@test "the bypass is honoured" {
	BATTEN_STOP_GUARD_BYPASS=1 run stop 'Worth noting the receipt is stale.'
	! kicked "$output"
}

@test "the guard never exits non-zero, so it cannot surface as a hook error" {
	# Exit 2 is the launcher Stop hook's channel at this same boundary; two hooks
	# both exiting 2 would stack error notices on one turn.
	run stop 'Worth noting the receipt is stale.'
	[ "$status" -eq 0 ]
	run stop 'Nothing to flag here.'
	[ "$status" -eq 0 ]
}

# --- wiring ------------------------------------------------------------------

@test "the Stop hook is registered in settings" {
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
cmds = [h['command'] for g in d['hooks']['Stop'] for h in g['hooks']]
assert any('stop-guard' in c for c in cmds), cmds
print('registered')"
	[ "$status" -eq 0 ]
	[[ "$output" == *"registered"* ]]
}

@test "the Stop entry declares no matcher, which the event does not support" {
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
for g in d['hooks']['Stop']:
    assert 'matcher' not in g, g
print('no matcher')"
	[ "$status" -eq 0 ]
}
