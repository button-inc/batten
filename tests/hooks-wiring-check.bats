#!/usr/bin/env bats
# subject: mise-tasks/hooks-wiring-check
#
# `hooks-wiring-check`'s decision table (CLOUD-62, widened by CLOUD-777).
#
# The gate answers one question — is batten registered exactly once on every
# hook surface every harness emits, matching what `generate hooks` derives — and
# the cases below are every way that can end. Fixture-fed and offline: each
# writes a wiring file and points the gate at it with `HOOKS_WIRING_HARNESSES`,
# so nothing here depends on this repository's own `.claude/settings.json`
# staying the shape it has today.
#
# THE CASE THIS FILE EXISTS FOR is `a command that reaches nothing is drift, not
# silence`. While the gate was being written its selector asked "does this
# command reach the engine", which made the selector and the check the same
# predicate: a typo in the launcher name did not fail the gate, it removed the
# entry from view, and the run reported "0 registrations agree" and exited 0.
# That is the false-green shape this repository keeps re-meeting, and the case
# below is what stops it coming back. The census case at the bottom is the same
# shape caught a second time, in this gate's own harness table.
#
# THREE CASES HERE INVERTED WITH CLOUD-777, and each is kept with its old reason
# rather than deleted, because the reason was right for the state it described:
#
#   * a wiring with no batten entry used to be GREEN ("installing them is
#     CLOUD-312's"). This is that cutover, so it is now red.
#   * a matcher on batten's entry used to be UNJUDGED ("a matcher derived from
#     the `Harness` enum would be the core asserting a vocabulary"). Still true,
#     and not what is asserted: the derivation emits no matcher at all, so what
#     is compared is its ABSENCE.
#   * a `Stop` sibling used to be out of scope ("PreToolUse ONLY"). CLOUD-312's
#     scope widened with it: the entry point is every point.

setup() {
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	GATE="$REPO/mise-tasks/hooks-wiring-check"
	WIRING="$BATS_TEST_TMPDIR/settings.json"
	# Empty by default, so a fixture is judged against ITSELF rather than against
	# this repository's twelve declared retirements — which would report all
	# twelve as stale on every case below. A case that wants a declaration sets it.
	DECLARED=""
	# One harness, and the fixture's whole universe stated explicitly. An UNSET
	# `HOOKS_WIRING_KNOWN` makes the gate read the real harness set and refuse to
	# guess; setting it here is a case saying "these are all the hosts there are",
	# which is what lets a one-harness fixture be green at all.
	KNOWN="claude-code"
}

# Run the gate over a wiring file, from the real repo (the derivation comes from
# the binary, which needs the real crate).
gate() {
	(cd "$REPO" &&
		HOOKS_WIRING_HARNESSES="claude-code $WIRING batten-hook.sh" \
			HOOKS_WIRING_KNOWN="$KNOWN" \
			HOOKS_WIRING_DECLARED_FOR="claude-code" \
			HOOKS_WIRING_DECLARED="$DECLARED" "$GATE")
}

# A COMPLETE claude-code wiring: batten once on each of the seven events that
# host emits, no matcher. This is the baseline every mutation below departs from,
# and its completeness is the point — under CLOUD-777 a partial wiring is not a
# smaller green, it is red.
complete_wiring() { # <command>
	local command="${1:-\$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh}"
	python3 - "$WIRING" "$command" <<-'PY'
		import json, sys
		path, command = sys.argv[1], sys.argv[2]
		events = ["PreToolUse", "PostToolUse", "Stop", "SessionStart",
		          "TaskCompleted", "ConfigChange", "PostToolBatch"]
		hooks = {e: [{"hooks": [{"type": "command", "command": command}]}] for e in events}
		open(path, "w").write(json.dumps({"hooks": hooks}, indent=2) + "\n")
	PY
}

# Drop one event from an otherwise complete wiring.
without_event() { # <event>
	python3 - "$WIRING" "$1" <<-'PY'
		import json, sys
		path, event = sys.argv[1], sys.argv[2]
		doc = json.load(open(path))
		doc["hooks"].pop(event, None)
		open(path, "w").write(json.dumps(doc, indent=2) + "\n")
	PY
}

# Add a key to one event's first entry, or a second command under it.
mutate_event() { # <event> <matcher|second> <value>
	python3 - "$WIRING" "$1" "$2" "$3" <<-'PY'
		import json, sys
		path, event, kind, value = sys.argv[1:5]
		doc = json.load(open(path))
		entry = doc["hooks"][event][0]
		if kind == "matcher":
		    entry["matcher"] = value
		else:
		    doc["hooks"][event].append(
		        {"hooks": [{"type": "command", "command": value}]})
		open(path, "w").write(json.dumps(doc, indent=2) + "\n")
	PY
}

@test "the launcher stands in for the derived command — that indirection is the point" {
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh'
	run gate
	[ "$status" -eq 0 ]
}

@test "the derived command itself is accepted, so a consumer without a launcher still passes" {
	complete_wiring 'batten hook --harness claude-code'
	run gate
	[ "$status" -eq 0 ]
}

@test "a command that reaches nothing is DRIFT, not silence" {
	# The false green this suite exists for: one byte off the launcher's name.
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook-typo.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-command-drift"* ]]
}

@test "the pointer names the file and the event, never the entry body" {
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook-typo.sh'
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
	complete_wiring
	mutate_event PreToolUse second 'x'
	python3 - "$WIRING" <<-'PY'
		import json, sys
		doc = json.load(open(sys.argv[1]))
		doc["hooks"]["NotAnEvent"] = doc["hooks"]["PreToolUse"][:1]
		doc["hooks"]["PreToolUse"] = doc["hooks"]["PreToolUse"][:1]
		open(sys.argv[1], "w").write(json.dumps(doc, indent=2) + "\n")
	PY
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-underived"* ]]
}

# --- CLOUD-777's three shown-able-to-fail cases (CLOUD-418) -------------------

@test "A MATCHER ON BATTEN'S OWN ENTRY IS A SECOND NARROWING, and is refused" {
	# Not "a matcher we disagree with" — any matcher. The host's absent-matcher
	# default is every tool, which is what lets `batten.toml`'s `mediated_call`
	# rows be the only narrowing. A matcher here re-narrows in a second place, and
	# a wrong one narrows enforcement silently: that is exactly how the
	# protected-write gate came to cover five tool names on one host (CLOUD-779).
	complete_wiring
	mutate_event PreToolUse matcher 'Bash|Write|Edit|MultiEdit|NotebookEdit'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-matcher-narrows"* ]]
}

@test "A SECOND COMMAND ON ONE EVENT is a second authority for one decision" {
	complete_wiring
	mutate_event PostToolUse second 'batten hook --harness claude-code'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-registered-2-times"* ]]
}

@test "A DERIVED EVENT WITH NO REGISTRATION is refused — this is CLOUD-312's cutover" {
	# The exemption this replaces: "an event the derivation emits that the wiring
	# does not yet register is not a failure. Installing the full set is
	# CLOUD-312's cutover obligation, not this gate's." That reasoning was right —
	# a gate red for another issue's reason gets bypassed — and it expires with
	# the issue, which CLOUD-777 landed.
	complete_wiring
	without_event ConfigChange
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-unregistered"* ]]
}

@test "a wiring carrying no batten entry is now RED, on every event it omits" {
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
	DECLARED="mise-tasks/stop-guard CLOUD-312"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-unregistered"* ]]
}

@test "a wiring with no hooks key at all is red rather than green" {
	# It used to be green: nothing claimed to be batten's, so nothing disagreed.
	# Under "registered on every surface" an empty file is the maximal disagreement.
	echo '{ "enabledMcpjsonServers": ["serena"] }' >"$WIRING"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-event-unregistered"* ]]
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
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook-typo.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"PreToolUse"* ]]
	[[ "$output" == *"Stop"* ]]
	[[ "$output" == *"7 wiring violation(s)"* ]]
}

# --- the harness census -------------------------------------------------------
#
# The table of `<harness> <file>` rows is a consumer's file layout, so it lives
# in the gate. Which harnesses EXIST is the core's answer, and the first attempt
# read it from `spec --json`, which carries no harness array: the query returned
# empty, the census compared nothing, and the gate reported green. Same false
# green as the selector above, one layer out.

@test "A HARNESS THE CORE KNOWS AND THE TABLE OMITS is refused" {
	complete_wiring
	KNOWN="claude-code
cursor"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-harness-unlisted"* ]]
}

@test "exit-code is exempt from the census: it has no hook-config surface" {
	complete_wiring
	KNOWN="claude-code
exit-code"
	run gate
	[ "$status" -eq 0 ]
}

@test "AN UNREADABLE CENSUS IS EXIT 2 — not an empty set that passes" {
	# The distinction the whole census rests on. `${VAR+set}` rather than
	# `${VAR:-}`: a case may STATE an empty universe, but a gate that could not
	# look must never report the table complete.
	complete_wiring
	# A real git checkout that is NOT this crate, so `cargo run -p batten` cannot
	# resolve a binary and the possible-values line never appears. Retrying the
	# SETUP, never the measurement: if the repo cannot be created the case has not
	# been established and says so rather than asserting on a premise it never made.
	elsewhere="$BATS_TEST_TMPDIR/not-the-crate"
	mkdir -p "$elsewhere"
	git -C "$elsewhere" init -q . || skip "could not establish a scratch repo (CLOUD-448 shape)"
	run env -u HOOKS_WIRING_KNOWN \
		HOOKS_WIRING_ROOT="$elsewhere" \
		HOOKS_WIRING_HARNESSES="claude-code $WIRING batten-hook.sh" \
		HOOKS_WIRING_DECLARED="" bash "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not read the harness set"* ]]
}

# --- the commands that are not batten's (CLOUD-713, widened by CLOUD-777) -----

# A complete wiring plus one other command under `event`.
with_sibling() { # <event> <sibling command>
	complete_wiring
	python3 - "$WIRING" "$1" "$2" <<-'PY'
		import json, sys
		path, event, command = sys.argv[1:4]
		doc = json.load(open(path))
		doc["hooks"][event].append(
		    {"matcher": ".*save_issue",
		     "hooks": [{"type": "command", "command": command}]})
		open(path, "w").write(json.dumps(doc, indent=2) + "\n")
	PY
}

@test "a PreToolUse command that does not reach the engine is a violation" {
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
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
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"issue-read-guard"* ]]
}

@test "a declared sibling passes, and the declaration names who retires it" {
	DECLARED="mise-tasks/issue-read-guard CLOUD-312"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 0 ]
}

@test "a declaration naming no issue is itself a violation, so the hatch is never silent" {
	DECLARED="mise-tasks/issue-read-guard"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration whose key is not a CLOUD row is unowned, not merely present" {
	DECLARED="mise-tasks/issue-read-guard someday"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration matching nothing wired is stale, so the list cannot rot" {
	# The direction that keeps a retirement honest: land the deletion, delete the
	# row. Left behind, it is a standing licence the next command with a similar
	# path inherits without anyone deciding to grant it.
	DECLARED="mise-tasks/retired-long-ago CLOUD-312"
	complete_wiring
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-stale"* ]]
}

@test "THE SCOPE IS EVERY EVENT NOW: a Stop sibling is a violation too" {
	# The inversion CLOUD-777 argues for directly: "CLOUD-312 is titled 'the
	# engine is the pre-tool entry point'. The entry point is every point." The
	# old scope note was not wrong about its own state — it declined to price
	# retiring a recorder like retiring a decision table — and the decision
	# reprices both: nothing else registers a hook.
	with_sibling Stop '$CLAUDE_PROJECT_DIR/mise-tasks/stop-guard'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-sibling-command"* ]]
	[[ "$output" == *"stop-guard"* ]]
}
