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
	# Empty by default, so a fixture is judged against ITSELF rather than against
	# this repository's six declared retirements — which would report all six as
	# stale on every case below. A case that wants a declaration sets it.
	DECLARED=""
}

# Run the gate over a wiring file, from the real repo (the derivation comes from
# the binary, which needs the real crate).
gate() {
	(cd "$REPO" && HOOKS_WIRING_FILE="$WIRING" HOOKS_WIRING_DECLARED="$DECLARED" "$GATE")
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
	[[ "$output" == *"2 wiring violation(s)"* ]]
}

# --- one command per PreToolUse event (CLOUD-713) -----------------------------
#
# The gate above judges the entries that ARE batten's. These judge the ones that
# are not: the engine registers one command per event and adjudicates from
# `batten.toml`, so a second command under `PreToolUse` is a second authority for
# one decision. Six of them accreted in this repository with nothing going red,
# one of them landing inside twenty minutes while the gate was being written.

# A wiring with the launcher plus one other PreToolUse command.
wiring_with_sibling() { # <sibling command>
	cat >"$WIRING" <<-JSON
		{
		  "hooks": {
		    "PreToolUse": [
		      {
		        "matcher": "Bash|Write",
		        "hooks": [
		          { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh" }
		        ]
		      },
		      {
		        "matcher": ".*save_issue",
		        "hooks": [
		          { "type": "command", "command": "$1" }
		        ]
		      }
		    ]
		  }
		}
	JSON
}

@test "a PreToolUse command that does not reach the engine is a violation" {
	wiring_with_sibling '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-sibling-command"* ]]
}

@test "the sibling IS named by its path, unlike a drifted batten command" {
	# Rule 4 permits a path — and here it is load-bearing rather than incidental:
	# the remedy differs per command (which guard to retire, under which issue),
	# so a bare count would name a problem nobody can act on. The drift case above
	# withholds its command for the opposite reason: the remedy there is the same
	# single edit whatever the command said.
	wiring_with_sibling '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"issue-read-guard"* ]]
}

@test "a declared sibling passes, and the declaration names who retires it" {
	DECLARED="mise-tasks/issue-read-guard CLOUD-312"
	wiring_with_sibling '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 0 ]
}

@test "a declaration naming no issue is itself a violation, so the hatch is never silent" {
	DECLARED="mise-tasks/issue-read-guard"
	wiring_with_sibling '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration whose key is not a CLOUD row is unowned, not merely present" {
	DECLARED="mise-tasks/issue-read-guard someday"
	wiring_with_sibling '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration matching nothing wired is stale, so the list cannot rot" {
	# The direction that keeps a retirement honest: land the deletion, delete the
	# row. Left behind, it is a standing licence the next command with a similar
	# path inherits without anyone deciding to grant it.
	DECLARED="mise-tasks/retired-long-ago CLOUD-312"
	wiring_with PreToolUse '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-stale"* ]]
}

@test "the scope is PreToolUse: a Stop command is not a sibling violation" {
	# Deliberate, and argued in the gate: the other events carry commands that are
	# not policy — a provisioner, two recorders that say out loud they gate
	# nothing. Sweeping them in would price retiring a sensor like retiring a
	# decision table.
	cat >"$WIRING" <<-'JSON'
		{
		  "hooks": {
		    "PreToolUse": [
		      { "hooks": [ { "type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh" } ] }
		    ],
		    "Stop": [
		      { "hooks": [ { "type": "command", "command": "$CLAUDE_PROJECT_DIR/mise-tasks/stop-guard" } ] }
		    ]
		  }
		}
	JSON
	run gate
	[ "$status" -eq 0 ]
}
