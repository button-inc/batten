#!/usr/bin/env bats
#
# `hooks-wiring-check`'s decision table (CLOUD-62).
#
# The gate answers one question — does every committed `batten hook`
# registration agree with what `generate hooks` derives — and the cases below are
# every way that can end. Fixture-fed and offline: each writes a wiring file and
# points the gate at it with `HOOKS_WIRING_FILE`, so nothing here depends on this
# repository's own `.claude/settings.json` staying the shape it has today.
#
# THE CASE THIS FILE EXISTS FOR is `a command that reaches nothing is drift, not
# silence`. While the gate was being written its selector asked "does this
# command reach the engine", which made the selector and the check the same
# predicate: a typo in the launcher name did not fail the gate, it removed the
# entry from view, and the run reported "0 registrations agree" and exited 0.
# That is the false-green shape this repository keeps re-meeting, and the case
# below is what stops it coming back.

setup() {
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	GATE="$REPO/mise-tasks/hooks-wiring-check"
	WIRING="$BATS_TEST_TMPDIR/settings.json"
}

# Run the gate over a wiring file, from the real repo (the derivation comes from
# the binary, which needs the real crate).
gate() {
	(cd "$REPO" && HOOKS_WIRING_FILE="$WIRING" "$GATE")
}

# A wiring whose one batten entry runs `command`.
wiring_with() { # <event> <command>
	cat >"$WIRING" <<-JSON
		{
		  "hooks": {
		    "$1": [
		      {
		        "matcher": "Bash|Write",
		        "hooks": [
		          { "type": "command", "command": "$2" }
		        ]
		      }
		    ]
		  }
		}
	JSON
}

@test "the launcher stands in for the derived command — that indirection is the point" {
	wiring_with PreToolUse '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh'
	run gate
	[ "$status" -eq 0 ]
}

@test "the derived command itself is accepted, so a consumer without a launcher still passes" {
	wiring_with PreToolUse 'batten hook --harness claude-code'
	run gate
	[ "$status" -eq 0 ]
}

@test "a command that reaches nothing is DRIFT, not silence" {
	# The false green this suite exists for: one byte off the launcher's name.
	wiring_with PreToolUse '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook-typo.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-command-drift"* ]]
}

@test "the pointer names the file and the event, never the entry body" {
	wiring_with PreToolUse '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook-typo.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"$WIRING:PreToolUse"* ]]
	# Non-negotiable rule 4: a count and a `path:event`, never the command that
	# drifted — the remedy is the same one edit either way.
	[[ "$output" != *"batten-hook-typo.sh"* ]]
}

@test "an event the derivation does not register is refused" {
	# A hook registered under an event the harness never emits can never fire:
	# installed, green to every other check, enforcing nothing.
	wiring_with NotAnEvent 'batten hook --harness claude-code'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-underived"* ]]
}

@test "a wiring carrying no batten entry is green, because installing them is CLOUD-312's" {
	cat >"$WIRING" <<-'JSON'
		{
		  "hooks": {
		    "Stop": [
		      {
		        "hooks": [
		          { "type": "command", "command": "$CLAUDE_PROJECT_DIR/mise-tasks/stop-guard" }
		        ]
		      }
		    ]
		  }
		}
	JSON
	run gate
	[ "$status" -eq 0 ]
}

@test "a wiring with no hooks key at all is green rather than an error" {
	echo '{ "enabledMcpjsonServers": ["serena"] }' >"$WIRING"
	run gate
	[ "$status" -eq 0 ]
}

@test "an ABSENT wiring file is exit 2 — could not look is not a verdict" {
	WIRING="$BATS_TEST_TMPDIR/does-not-exist.json"
	run gate
	[ "$status" -eq 2 ]
}

@test "an unparseable wiring file is exit 2, never a silent pass" {
	printf 'not json at all\n' >"$WIRING"
	run gate
	[ "$status" -eq 2 ]
}

@test "every registration is judged, so one run names them all" {
	cat >"$WIRING" <<-'JSON'
		{
		  "hooks": {
		    "PreToolUse": [
		      { "hooks": [ { "type": "command", "command": "batten-hook-typo.sh" } ] }
		    ],
		    "Stop": [
		      { "hooks": [ { "type": "command", "command": "batten-also-wrong.sh" } ] }
		    ]
		  }
		}
	JSON
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"PreToolUse"* ]]
	[[ "$output" == *"Stop"* ]]
	[[ "$output" == *"2 registration(s) disagree"* ]]
}
