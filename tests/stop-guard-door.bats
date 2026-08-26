#!/usr/bin/env bats
# subject: mise-tasks/stop-guard.sh, through `batten hook`
#
# THE SECOND TIER FOR CLOUD-312 ROW 9, and CLOUD-312's differential obligation:
# the retiring registration's fixtures replay through the door before the
# registration is deleted. `tests/stop-guard.bats` runs the script directly,
# which cannot answer the question that broke the previous migration — whether
# the ENGINE can consume what this script produces.
#
# THIS ONE IS THE INTERESTING CASE OF THE THREE, because the answer travels a
# channel the other two do not use. The guard's reply is an ADVISORY, not a
# verdict: stdout on exit 0 is advice the engine merges, `AdvisoryReach` lists
# `Stop` for this host, and what the model receives is the same
# `additionalContext` document the script used to build by hand. So the whole
# migration is that one substitution — and getting it wrong is silent, which is
# exactly how `connector-allow-guard` spent its life behind the door deciding
# nothing.
#
# EVERY CASE DRIVES THE TELL, and that is a cost decision rather than a coverage
# one. This guard runs five rules, and rules 3-5 run only when the ones above
# them found nothing — so a message carrying the tell answers in milliseconds
# while a clean one pays the whole ladder. That asymmetry is measured and
# recorded on the handler's row in `batten.toml`; what this file needs from the
# guard is its ANSWER, which the first rule produces.

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
	# Copied from the suite's own tree, so `mise run mutant` reaches this tier.
	cp "$BATS_TEST_DIRNAME/../mise-tasks/stop-guard.sh" "$REPO/mise-tasks/"
	cp "$BATS_TEST_DIRNAME/../mise-tasks/stop-posture-check.sh" "$REPO/mise-tasks/"
	cp "$BATS_TEST_DIRNAME/../mise-tasks/payload-field.sh" "$REPO/mise-tasks/"

	{
		echo "version = 1"
		echo
		echo "[[hook.handler]]"
		echo 'id = "stop-guard"'
		echo 'on = "stop"'
		echo 'run = ["mise-tasks/stop-guard.sh"]'
		echo "timeout_ms = 90000"
		echo 'owner = "CLOUD-892"'
		echo 'expires = "2027-02-28"'
	} >"$REPO/batten.toml"
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"

	export BATTEN_BIN="$BIN"
}

# Called directly, never through `run`: `run` executes in a subshell and would
# discard both assignments, leaving every negative assertion comparing an empty
# string.
door() { # door <last_assistant_message> [stop_hook_active]
	local envelope
	envelope=$(jq -nc --arg m "$1" --argjson a "${2:-false}" \
		'{hook_event_name:"Stop",session_id:"s",cwd:".",
		  transcript_path:"/nonexistent.jsonl",
		  stop_hook_active:$a,last_assistant_message:$m}')
	(
		cd "$REPO" || exit 1
		printf '%s' "$envelope" | "$BIN" hook --harness claude-code \
			>"$BATS_TEST_TMPDIR/door.out" 2>"$BATS_TEST_TMPDIR/door.err"
	)
	DOOR_OUT=$(cat "$BATS_TEST_TMPDIR/door.out")
	DOOR_ERR=$(cat "$BATS_TEST_TMPDIR/door.err")
}

@test "THE MEASURED DEFECT: no host document the handler wrote is forwarded" {
	# ASSERTED OVER STDOUT, WHICH IS WHERE THE VIOLATION ACTUALLY LANDS HERE.
	# `dispatch_handlers` appends contract violations to the same advice vector
	# the advisory rides, and `AdvisoryReach` lists `Stop` — so at this event a
	# violation is rendered INTO the `additionalContext` document rather than
	# written to the engine's stderr. Measured, because the first version of this
	# row asserted over stderr, which is empty at `Stop` whatever happens, and
	# passed for that reason alone.
	door 'The rebase is clean. Worth noting that the lock file still drifts.'
	[[ "$DOOR_OUT" != *"wrote a host decision document"* ]]
	[[ "$DOOR_OUT" != *"hook.handler stop-guard:"* ]]
}

@test "the kick reaches the model as the engine's own advisory" {
	# THE ROW THE MIGRATION IS FOR. `additionalContext` is what the host reads at
	# `Stop`, and it is now the ENGINE's spelling of the handler's advice rather
	# than a document the script wrote — the two are byte-similar and one of them
	# is silently discarded.
	door 'The rebase is clean. Worth noting that the lock file still drifts.'
	[[ "$DOOR_OUT" == *'"additionalContext"'* ]]
	[[ "$DOOR_OUT" == *'"Stop"'* ]]
	[[ "$DOOR_OUT" == *"hedged-flag-framing"* ]]
}

@test "a refusal is structurally unavailable here, so the turn always ends" {
	# `Event::carries_a_verdict` is false at `Stop`, so even a handler exiting 2
	# has its refusal demoted to advice — the loophole `lib.rs` names, and the
	# reason the CLOUD-889 runaway cannot come back through this row. Asserted
	# over the emitted document because that is where a deny would have to appear.
	door 'The rebase is clean. Worth noting that the lock file still drifts.'
	[[ "$DOOR_OUT" != *'"permissionDecision"'* ]]
	[[ "$DOOR_OUT" != *'"deny"'* ]]
}

@test "the re-entry caused by a previous kick is silent through the door too" {
	# The bound that makes this one nudge per turn rather than a runaway. It is
	# the guard's own predicate over `stop_hook_active`, and it reads the host's
	# payload — which the door hands through unchanged, and which is the one
	# property a reader would reasonably fear the extra hop loses.
	door 'Worth noting the drift.' true
	[[ "$DOOR_OUT" != *"hedged-flag-framing"* ]]
	[[ "$DOOR_ERR" != *"hook.handler stop-guard:"* ]]
}

@test "the impersonation detector is live behind this row, not merely defined" {
	# THE POSITIVE CONTROL. Every negative row above is also satisfied by a
	# handler that never ran, so one row makes this one write the host document on
	# purpose and requires the door to name it — and to drop it.
	cat >"$REPO/mise-tasks/stop-guard.sh" <<-'SH'
		#!/usr/bin/env bash
		printf '{"hookSpecificOutput":{"hookEventName":"Stop","additionalContext":"SENTINELXYZZY"}}\n'
	SH
	chmod +x "$REPO/mise-tasks/stop-guard.sh"
	door 'anything at all'
	[[ "$DOOR_OUT" == *"hook.handler stop-guard: wrote a host decision document"* ]]
	# The document it tried to write is DROPPED, not merged: its payload never
	# reaches the model, which is the half that made this defect silent.
	[[ "$DOOR_OUT" != *SENTINELXYZZY* ]]
}

@test "the re-entry bound is the reason the violation above is not a runaway" {
	# The engine relays a violation into the same channel the advisory uses, so a
	# broken handler at `Stop` speaks once per turn rather than once per Stop —
	# and it is the HANDLER's `stop_hook_active` read that bounds it, which a
	# broken handler by definition may not be doing. Asserted here because it is
	# the one place the two interact.
	cat >"$REPO/mise-tasks/stop-guard.sh" <<-'SH'
		#!/usr/bin/env bash
		printf '{"hookSpecificOutput":{"hookEventName":"Stop","additionalContext":"SENTINELXYZZY"}}\n'
	SH
	chmod +x "$REPO/mise-tasks/stop-guard.sh"
	door 'anything at all' true
	# Still reported on the re-entry, because the engine cannot know the handler
	# meant to stop — which is the cost of a broken handler, stated rather than
	# assumed away, and exactly what the contract violation is telling the reader
	# to go and fix.
	[[ "$DOOR_OUT" == *"wrote a host decision document"* ]]
	[[ "$DOOR_OUT" != *SENTINELXYZZY* ]]
}
