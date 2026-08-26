#!/usr/bin/env bats
# subject: mise-tasks/run-shape-guard.sh, through `batten hook`
#
# THE SECOND TIER FOR CLOUD-312 ROW 4, and CLOUD-312's own differential
# obligation: the retiring registration's fixtures replay through the door before
# the registration is deleted. `tests/run-shape-guard.bats` runs the script
# directly, which cannot answer the question that actually broke the previous
# migration — whether the ENGINE can consume what this script produces.
#
# It broke exactly once and silently: `connector-allow-guard` went behind the
# door still writing `hookSpecificOutput` on stdout, which is
# `Violation::ImpersonatedHost` — reported and never forwarded — so every verdict
# it produced was discarded for the life of the migration and no suite noticed.
# This file is the row that would have.
#
# THE FIXTURE REPOSITORY CARRIES ONE HANDLER ROW AND NO `[[rule]]` AT ALL. That
# isolation is the whole design: `verdict-not-discarded` and the other mediated
# rows in the real `batten.toml` refuse commands in this same family, so driving
# the real config would let an engine row's verdict stand in for the handler's —
# which is the substitution that hid the defect the first time.

setup() {
	BIN=""
	for candidate in \
		"${BATTEN_BIN:-}" \
		"$BATS_TEST_DIRNAME/../target/release/batten" \
		"$BATS_TEST_DIRNAME/../target/debug/batten"; do
		[ -n "$candidate" ] && [ -x "$candidate" ] || continue
		BIN="$candidate"
		break
	done
	[ -n "$BIN" ] || BIN="$(command -v batten || true)"
	[ -n "$BIN" ] || skip "no batten binary to drive"

	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/mise-tasks"
	# Copied from the suite's own tree, so `mise run mutant` reaches this tier:
	# under `mutant` that tree is the mutated one.
	cp "$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard.sh" "$REPO/mise-tasks/"
	cp "$BATS_TEST_DIRNAME/../mise-tasks/payload-field.sh" "$REPO/mise-tasks/"
	# The guard resolves `mise.toml` beside itself for the cargo family. An empty
	# one keeps that arm defined and silent; the cargo family's own corpus stays
	# in the direct suite, where a fixture `mise.toml` is what it is testing.
	printf '[tools]\n' >"$REPO/mise.toml"

	{
		echo "version = 1"
		echo
		echo "[[hook.handler]]"
		echo 'id = "run-shape-guard"'
		echo 'on = "pre-tool"'
		echo 'run = ["mise-tasks/run-shape-guard.sh"]'
		echo 'matcher = "Bash"'
		echo "timeout_ms = 8000"
		echo 'owner = "CLOUD-613"'
		echo 'expires = "2027-02-28"'
	} >"$REPO/batten.toml"
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"

	# `payload-field` resolves the real binary, so the guard reads the two fields
	# it depends on rather than failing open on every call — which is how a suite
	# reports every deny row red and every mutation aimed at one "already caught".
	export BATTEN_BIN="$BIN"
}

# Called DIRECTLY, never through `run`: `run` executes in a subshell, so these
# two assignments would be discarded and every negative assertion below would
# compare an empty string and pass.
door() { # door <command> [run_in_background]
	local envelope
	if [ -n "${2:-}" ]; then
		envelope=$(jq -nc --arg c "$1" '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$c,run_in_background:true}}')
	else
		envelope=$(jq -nc --arg c "$1" '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$c}}')
	fi
	(
		cd "$REPO" || exit 1
		printf '%s' "$envelope" | "$BIN" hook --harness claude-code \
			>"$BATS_TEST_TMPDIR/door.out" 2>"$BATS_TEST_TMPDIR/door.err"
	)
	DOOR_OUT=$(cat "$BATS_TEST_TMPDIR/door.out")
	DOOR_ERR=$(cat "$BATS_TEST_TMPDIR/door.err")
}

denied() { [[ "$DOOR_OUT" == *'"permissionDecision":"deny"'* ]]; }
allowed() { [[ "$DOOR_OUT" != *'"deny"'* ]]; }
# Nothing the door reports about the handler ITSELF — which is different from
# "the handler said nothing", and is the distinction this whole file exists for.
unbroken() { [[ "$DOOR_ERR" != *"hook.handler run-shape-guard:"* ]]; }

@test "THE MEASURED DEFECT: no host document the handler wrote is forwarded" {
	door 'cd /tmp; sleep 90; git log --oneline -1'
	[[ "$DOOR_ERR" != *"wrote a host decision document"* ]]
	unbroken
}

@test "a foreground sleep is refused THROUGH the door, and the reason travels" {
	door 'cd /tmp; sleep 90; git log --oneline -1'
	denied
	# Attributed to the handler by the engine, which is the difference between a
	# verdict that travelled and one the script printed to itself.
	[[ "$DOOR_OUT" == *"hook.handler.run-shape-guard"* ]]
	[[ "$DOOR_OUT" == *foreground* ]]
}

@test "a backgrounded timer is refused too, so the CALL's own fact reached it" {
	# The load-bearing case for the migration. This predicate is over
	# `run_in_background`, a property of the call rather than of the command
	# string, and it is the one thing a reader would reasonably fear the extra hop
	# loses. It does not: a handler receives the host's own payload.
	door 'sleep 590; tail -6 /tmp/land.log' bg
	denied
	[[ "$DOOR_OUT" == *TIMER* ]]
}

@test "a backgrounded wait on a condition stays allowed" {
	# The half without which the row above proves nothing: a guard that refused
	# every backgrounded sleep would satisfy it and be the false positive that
	# gets a guard switched off (CLOUD-418).
	door 'until [ -f /tmp/done ]; do sleep 1; done' bg
	allowed
	unbroken
}

@test "a git commit that can never obtain a message is refused through the door" {
	door "$(printf 'git add -A && git commit -F - >log 2>&1 && mise run land >l2 2>&1 <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	denied
	[[ "$DOOR_OUT" == *'-F <path>'* ]]
}

@test "an ordinary command is none of this guard's business, and costs no verdict" {
	door 'ls -la'
	allowed
	[ -z "$DOOR_ERR" ]
}

@test "a non-Bash tool never reaches the handler at all" {
	# `matcher` is the engine's narrowing, not the script's, so it is only
	# assertable here. Without it this row costs a spawn on every mediated call.
	local envelope
	envelope='{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}'
	(
		cd "$REPO" || exit 1
		printf '%s' "$envelope" | "$BIN" hook --harness claude-code \
			>"$BATS_TEST_TMPDIR/door.out" 2>"$BATS_TEST_TMPDIR/door.err"
	)
	DOOR_OUT=$(cat "$BATS_TEST_TMPDIR/door.out")
	DOOR_ERR=$(cat "$BATS_TEST_TMPDIR/door.err")
	allowed
	[ -z "$DOOR_ERR" ]
}

@test "the impersonation detector is live behind this row, not merely defined" {
	# THE POSITIVE CONTROL. Every negative row above is also satisfied by a
	# handler that never ran, so one row makes this one write the host document on
	# purpose and requires the door to name it.
	cat >"$REPO/mise-tasks/run-shape-guard.sh" <<-'SH'
		#!/usr/bin/env bash
		printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}\n'
	SH
	chmod +x "$REPO/mise-tasks/run-shape-guard.sh"
	door 'ls -la'
	[[ "$DOOR_ERR" == *"hook.handler run-shape-guard: wrote a host decision document"* ]]
	allowed
}

@test "the bypass reaches the handler through the door" {
	# A refusal whose bypass cannot be reached is not a remedy (§5). The engine
	# passes the environment through, so the guard's own hatch still works from
	# behind the door — which is not automatic and is worth one row.
	local envelope
	envelope=$(jq -nc '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:"cd /tmp; sleep 90; echo done"}}')
	(
		cd "$REPO" || exit 1
		printf '%s' "$envelope" | BATTEN_RUN_SHAPE_BYPASS=1 "$BIN" hook --harness claude-code \
			>"$BATS_TEST_TMPDIR/door.out" 2>"$BATS_TEST_TMPDIR/door.err"
	)
	DOOR_OUT=$(cat "$BATS_TEST_TMPDIR/door.out")
	DOOR_ERR=$(cat "$BATS_TEST_TMPDIR/door.err")
	allowed
	unbroken
}
