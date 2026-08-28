#!/usr/bin/env bats
# subject: mise-tasks/hooks-wiring-check.sh
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

# A WHOLE FIXTURE ROOT, NOT ONE FILE, SINCE CLOUD-777 MOVED THE DERIVATION
# IN-PROCESS. `batten doctor hooks` reads the harness surfaces under its own cwd
# and ranges over `Harness::ALL`, so a fixture carrying one file would report four
# `file-missing` rows before any mutation was reached. Every harness's wiring is
# materialized from the emitter, and each case mutates the one it is about —
# which is stronger than the old one-file shape rather than weaker: the other four
# are asserted green in the same run.
setup() {
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	GATE="$REPO/mise-tasks/hooks-wiring-check.sh"
	ROOT="$BATS_TEST_TMPDIR/root"
	# A HOME that is NOT the fixture root, deliberately. A host's user-level
	# surface and its project-level one share a spelling, so pointing HOME at the
	# checkout makes them one file — which is a fact about the fixture, not about
	# the wiring, and it reported every one of batten's own registrations as a
	# merged second authority until this line existed.
	FIXTURE_HOME="$BATS_TEST_TMPDIR/home"
	WIRING="$ROOT/.claude/settings.json"
	# Empty by default, so a fixture is judged against ITSELF rather than against
	# this repository's declared retirements — which would report every one as
	# stale on every case below. A case that wants a declaration sets it.
	DECLARED=""
	# Empty for the reason DECLARED is (CLOUD-525): the merged surfaces are files
	# under the real `$HOME`, and a suite that read them would judge every case
	# against whatever the developer's launcher happens to have provisioned. A
	# case about a MERGED surface sets this and points HOME at the fixture root.
	MERGED=""
	# The table under test. Empty means "the fixture root's own", built in `gate`;
	# a case about the TABLE sets it.
	HARNESSES=""
	mkdir -p "$ROOT/.claude" "$ROOT/.cursor" "$ROOT/.codex" "$ROOT/.github/hooks" "$ROOT/.gemini"
	mkdir -p "$FIXTURE_HOME/.claude" "$FIXTURE_HOME/.gemini"
	for harness in claude-code cursor copilot-cli gemini-cli codex-cli; do
		emit_wiring "$harness"
	done
}

# The derived wiring for one harness, written where that harness reads it.
#
# Emitted rather than typed: these are what the binary derives, so a hand-copied
# fixture would drift from the derivation the gate compares against and start
# failing for a reason no case here is about.
emit_wiring() { # <harness>
	local path derived
	case "$1" in
	claude-code) path="$ROOT/.claude/settings.json" ;;
	cursor) path="$ROOT/.cursor/hooks.json" ;;
	copilot-cli) path="$ROOT/.github/hooks/batten.json" ;;
	gemini-cli) path="$ROOT/.gemini/settings.json" ;;
	codex-cli) path="$ROOT/.codex/hooks.json" ;;
	esac
	derived=$(cd "$REPO" && cargo run --quiet -p batten -- generate hooks --harness "$1")
	# A `Key` harness emits the key's VALUE; the committed file wraps it. A
	# `Whole` one emits the document. One expression writes both, mirroring
	# `WiringFile`'s split rather than guessing at it.
	case "$1" in
	claude-code | gemini-cli) printf '{"hooks":%s}\n' "$derived" >"$path" ;;
	*) printf '%s\n' "$derived" >"$path" ;;
	esac
}

# Run the gate over the fixture root.
gate() {
	local table="${HARNESSES:-claude-code $WIRING -
cursor $ROOT/.cursor/hooks.json -
copilot-cli $ROOT/.github/hooks/batten.json -
gemini-cli $ROOT/.gemini/settings.json -
codex-cli $ROOT/.codex/hooks.json -}"
	(cd "$REPO" &&
		HOME="$FIXTURE_HOME" \
			HOOKS_WIRING_ROOT="$ROOT" \
			HOOKS_WIRING_HARNESSES="$table" \
			HOOKS_WIRING_DECLARED_FOR="claude-code" \
			HOOKS_WIRING_MERGED="$MERGED" \
			HOOKS_WIRING_DECLARED="$DECLARED" "$GATE")
}

# A merged surface for claude-code under the fixture HOME (CLOUD-525): a
# launcher-provisioned file the repository does not own and cannot delete.
with_merged() { # <event> <command>
	# No nested block in the Python: `<<-` strips leading TABS, so a body whose
	# inner indentation is a tab arrives flattened and unparseable. One expression,
	# no `with`, and the relative indentation problem cannot arise.
	python3 -c 'import json,sys; json.dump({"hooks": {sys.argv[2]: [{"hooks": [{"type": "command", "command": sys.argv[3]}]}]}}, open(sys.argv[1], "w"))' \
		"$FIXTURE_HOME/.claude/launcher-settings.json" "$1" "$2"
}

# One `get_issue` payload for the owner-liveness rule to read (CLOUD-525 §7(e)).
board() { # <json>
	printf '%s\n' "$1" >"$BATS_TEST_TMPDIR/board.json"
}

# `gate`, with the board piped in. A separate helper rather than a flag on
# `gate`, so a case that supplies no board reads as one that supplies none.
gate_with_board() {
	gate <"$BATS_TEST_TMPDIR/board.json"
}

# A COMPLETE claude-code wiring: batten once on each of the eight events that
# host emits, no matcher. This is the baseline every mutation below departs from,
# and its completeness is the point — under CLOUD-777 a partial wiring is not a
# smaller green, it is red.
complete_wiring() { # <command>
	local command="${1:-batten hook --harness claude-code}"
	python3 - "$WIRING" "$command" <<-'PY'
		import json, sys
		path, command = sys.argv[1], sys.argv[2]
		events = ["PreToolUse", "PostToolUse", "Stop", "SessionStart",
		          "TaskCompleted", "ConfigChange", "PostToolBatch",
		          "UserPromptSubmit"]
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

# THE AFFORDANCE, NOT THIS REPOSITORY'S WIRING. CLOUD-824 deleted
# `.claude/hooks/batten-hook.sh`, so every committed row is `-` and held to the
# derived command exactly. The column survives because the reason for it does:
# naming a consumer's file layout from `crates/batten` is what non-negotiable
# rule 1 forbids, so a consumer that DOES need an indirection resolves it in its
# own gate — and the only way that decision is testable is a fixture that uses
# one, which is what `HOOKS_WIRING_HARNESSES` is for.
@test "a declared launcher stands in for the derived command — that indirection is the point" {
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-launcher.sh'
	HARNESSES="claude-code $WIRING batten-launcher.sh
cursor $ROOT/.cursor/hooks.json -
copilot-cli $ROOT/.github/hooks/batten.json -
gemini-cli $ROOT/.gemini/settings.json -
codex-cli $ROOT/.codex/hooks.json -"
	run gate
	[ "$status" -eq 0 ]
}

@test "an UNDECLARED launcher is drift — the column is a declaration, not a wildcard" {
	# The other half of the case above, and the one that makes it a decision: the
	# core reports `command-drift` for anything that is not the derived command,
	# and only a row naming the launcher stands it down. Without this, "a launcher
	# passes" would be indistinguishable from "the drift check does not run".
	complete_wiring '$CLAUDE_PROJECT_DIR/.claude/hooks/batten-launcher.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-command-drift"* ]]
}

@test "the derived command itself is accepted, so a consumer without a launcher still passes" {
	complete_wiring 'batten hook --harness claude-code'
	run gate
	[ "$status" -eq 0 ]
}

@test "a command that reaches nothing is DRIFT, not silence" {
	# The false green this suite exists for: one byte off the derived command.
	complete_wiring 'batten hoook --harness claude-code'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-command-drift"* ]]
}

@test "the pointer names the file and the event, never the entry body" {
	complete_wiring 'batten hoook --harness claude-code'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"$WIRING:PreToolUse"* ]]
	# Non-negotiable rule 4: a count and a `path:event`, never the command that
	# drifted — the remedy is the same one edit either way.
	[[ "$output" != *"hoook"* ]]
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
	# `n`, not `2`. A reason id is a stable token — `&'static str` on the `Check`
	# it came from — and interpolating the count would make the byte-stability §6
	# asks for a function of the fixture. The count is in the row's
	# `registrations` field for a reader who wants it.
	[[ "$output" == *"wiring-event-registered-n-times"* ]]
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
		          { "type": "command", "command": "$CLAUDE_PROJECT_DIR/mise-tasks/stop-guard.sh" }
		        ]
		      }
		    ]
		  }
		}
	JSON
	DECLARED="mise-tasks/stop-guard.sh CLOUD-312"
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

@test "an ABSENT wiring file is a FINDING now, which is stronger than exit 2" {
	# It used to be "could not look". Since the derivation moved in-process the
	# core knows which file each harness declares, so an absent one is not an
	# unanswerable question — it is an unwired harness, named as one. Exit 1, and
	# the reason says which.
	rm "$WIRING"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-file-missing"* ]]
}

@test "an unparseable wiring file is named distinctly from an absent one" {
	# Two different remedies — write one, or fix one — so one reason id for both
	# would send the reader to the wrong place.
	printf 'not json at all\n' >"$WIRING"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-file-unreadable"* ]]
	[[ "$output" != *"wiring-file-missing"* ]]
}

@test "a diagnosis that cannot be READ is exit 2 — could not look is not a verdict" {
	# The distinction survives the move, one layer up: a missing FILE is an answer
	# the core gives, and a missing ANSWER is not an answer at all. A gate that
	# read an empty document as "nothing wrong" is the false green this file keeps
	# re-meeting, one layer further out each time.
	HOOKS_WIRING_DIAGNOSIS="true" run gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not look"* ]]
}

@test "a diagnosis that is not the DOCUMENT is exit 2 too, not a pass" {
	# Output alone is not an answer: a stub that prints valid JSON of the wrong
	# shape must not read as a healthy set of zero harnesses.
	HOOKS_WIRING_DIAGNOSIS="echo {}" run gate
	[ "$status" -eq 2 ]
}

@test "every registration is judged, so one run names them all" {
	complete_wiring 'batten hoook --harness claude-code'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"PreToolUse"* ]]
	[[ "$output" == *"Stop"* ]]
	[[ "$output" == *"8 wiring violation(s)"* ]]
}

# THE INSTANCE, ASSERTED OVER THE COMMITTED TABLE (CLOUD-824 §7). Every case
# above runs against a fixture, which is what makes the launcher affordance
# testable and also what makes it unable to say anything about THIS repository.
# This one reads the gate's own default table: no harness declares a launcher, so
# no shell can sit in front of the engine and decide which directory it reads its
# authority from. That is the class the deleted launcher belonged to — a shell
# resolver only becomes the engine's root-decider by being invoked in its place —
# and it is closed by the table rather than by the file being gone.
#
# `.claude/hooks/session-start.sh` still asks git for a root and is deliberately
# NOT covered: it resolves which checkout to PROVISION, not which authority to
# adjudicate against, and in a linked worktree the worktree is the right answer to
# that question. Reading the two as one class is what let the launcher's `cd`
# survive review.
@test "no harness declares a launcher, so no shell fronts the engine here" {
	local table
	table=$(sed -n '/^HARNESSES="\${HOOKS_WIRING_HARNESSES-/,/}"$/p' "$GATE")
	[ -n "$table" ]
	# Field 3 is the launcher column; every row must be `-`.
	run bash -c "printf '%s' \"\$1\" | sed -e 's/^HARNESSES=.*HARNESSES-//' -e 's/}\"\$//' | awk 'NF{print \$3}'" _ "$table"
	[ "$status" -eq 0 ]
	[ -n "$output" ]
	while read -r launcher; do
		[ "$launcher" = "-" ] || {
			echo "a harness row declares the launcher '$launcher'" >&2
			return 1
		}
	done <<<"$output"
	[ ! -e "$BATS_TEST_DIRNAME/../.claude/hooks/batten-hook.sh" ]
}

# --- the harness census -------------------------------------------------------
#
# The table of `<harness> <file>` rows is a consumer's file layout, so it lives
# in the gate. Which harnesses EXIST is the core's answer, and the first attempt
# read it from `spec --json`, which carries no harness array: the query returned
# empty, the census compared nothing, and the gate reported green. Same false
# green as the selector above, one layer out.

@test "A HARNESS THE CORE DIAGNOSES AND THE TABLE OMITS is refused" {
	# The core ranges over `Harness::ALL`, so it diagnoses `cursor` whether or not
	# this table mentions it — and a finding for a harness with no row here has no
	# file to point at and no launcher column to consult. Reporting it as
	# `unlisted` is what stops that being silent.
	rm "$ROOT/.cursor/hooks.json"
	HARNESSES="claude-code $WIRING -"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-harness-unlisted"* ]]
}

@test "A HARNESS THE TABLE NAMES AND THE CORE DOES NOT KNOW is refused too" {
	# The census inverted, which is what moving the derivation in-process did to
	# it. It used to ask "does the table cover every harness the core knows",
	# because a table covering five of six would report green over exactly the gap
	# the gate exists to close. The core answers that itself now. What is left is
	# the other direction: a row for a host that no longer exists, whose file path
	# and launcher column would read as live.
	HARNESSES="claude-code $WIRING -
cursor $ROOT/.cursor/hooks.json -
copilot-cli $ROOT/.github/hooks/batten.json -
gemini-cli $ROOT/.gemini/settings.json -
codex-cli $ROOT/.codex/hooks.json -
some-retired-host $ROOT/.retired/hooks.json -"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-harness-unknown"* ]]
}

@test "exit-code is absent from the diagnosis: it has no hook-config surface" {
	# The neutral contract — envelope in, decision as exit status out — has no
	# file to register in, so `Harness::wiring` returns `None` and it never
	# reaches the table. Asserted here because a row for it would be reported
	# `unknown`, which is the observable form of the exemption.
	run gate
	[ "$status" -eq 0 ]
	[[ "$output" != *"exit-code"* ]]
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
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard.sh'
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
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"issue-read-guard"* ]]
}

@test "a declared sibling passes, and the declaration names who retires it" {
	DECLARED="mise-tasks/issue-read-guard.sh CLOUD-312"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard.sh'
	run gate
	[ "$status" -eq 0 ]
}

@test "a declaration naming no issue is itself a violation, so the hatch is never silent" {
	DECLARED="mise-tasks/issue-read-guard.sh"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration whose key is not a CLOUD row is unowned, not merely present" {
	DECLARED="mise-tasks/issue-read-guard.sh someday"
	with_sibling PreToolUse '$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-unowned"* ]]
}

@test "a declaration matching nothing wired is stale, so the list cannot rot" {
	# The direction that keeps a retirement honest: land the deletion, delete the
	# row. Left behind, it is a standing licence the next command with a similar
	# path inherits without anyone deciding to grant it.
	DECLARED="mise-tasks/retired-long-ago.sh CLOUD-312"
	complete_wiring
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-stale"* ]]
}

# --- CLOUD-525: the surfaces the host MERGES, which no gate could see ---------
#
# The state the tree was in when this landed: `Stop` ran three handlers at
# runtime and `SessionStart` four, while every gate read two and three and
# reported green. These four cases are the census that closes it, and (a) is the
# discriminator — it is red on a fixture reproducing exactly that state.

@test "CLOUD-525 (a): an UNDECLARED registration on a merged surface is a violation" {
	MERGED="claude-code .claude/launcher-settings.json"
	complete_wiring
	with_merged Stop '~/.claude/stop-hook-git-check.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-sibling-command"* ]]
	# Named by SURFACE CLASS and basename, never by path: a merged file lives
	# under `$HOME` and differs per machine (§5).
	[[ "$output" == *"claude-code:merged:Stop:stop-hook-git-check.sh"* ]]
	[[ "$output" != *"$FIXTURE_HOME"* ]]
}

@test "CLOUD-525 (b): the same registration declared with an owner passes" {
	# A census, not a demand. The launcher's registrations are re-provisioned
	# mid-session and cannot be deleted from here, so they are RECORDED with an
	# owner — an added one becomes visible instead of silent, and no run goes red
	# on state this repo cannot fix.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="stop-hook-git-check.sh CLOUD-605"
	complete_wiring
	with_merged Stop '~/.claude/stop-hook-git-check.sh'
	run gate
	[ "$status" -eq 0 ]
}

@test "CLOUD-525 (c): a declared row matching nothing on a surface that WAS read is stale" {
	# The launcher file EXISTS and registers something else, so the surface was
	# opened and the row genuinely matches nothing — a launcher hook that went away
	# without taking its licence with it. That is the state this rule is for.
	MERGED="claude-code .claude/launcher-settings.json"
	# The other hook is declared too, so `stale` is the ONLY finding and the case
	# cannot pass on case (a)'s `wiring-sibling-command` instead.
	DECLARED="stop-hook-git-check.sh CLOUD-605
some-other-hook.sh CLOUD-605"
	complete_wiring
	with_merged Stop '~/.claude/some-other-hook.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-stale"* ]]
	[[ "$output" == *"stop-hook-git-check.sh"* ]]
	# EXACTLY ONE violation, which is how this case proves it did not pass on
	# case (a)'s `wiring-sibling-command` instead. Asserted through the COUNT
	# rather than by matching the reason's absence in `$output`: the summary line
	# names `wiring-sibling-command` in its own remedy text, so a substring test
	# for it matches the guidance on every red run and never the finding.
	[[ "$output" == *"1 wiring violation(s)"* ]]
}

@test "CLOUD-525 (c2): NO MERGED SURFACE READ IS COULD-NOT-LOOK, never a stale row" {
	# What (c) used to assert, inverted, because (c)'s premise was the defect.
	# With the launcher file ABSENT nothing was opened, so asking whether that
	# surface still registers the row answers a question nobody looked at — and it
	# answered "stale". Measured: green on a box whose launcher provisioned one,
	# red on every CI run, which is the verify/CI disagreement `land` stops on and
	# the same "red on state this repo cannot fix" (b) is written against.
	#
	# A CI runner is PERMANENTLY this state — no launcher ever provisions a file
	# there — so the old reading made two rows unlandable rather than merely noisy.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="stop-hook-git-check.sh CLOUD-605"
	complete_wiring
	run gate
	[ "$status" -eq 0 ]
	[[ "$output" != *"wiring-declaration-stale"* ]]
}

@test "CLOUD-525 (c3): a COMMITTED row is stale with no merged surface, as before" {
	# The narrowing is scoped to merged-surface rows and must not leak into the
	# committed ones — those name a path this repository owns and can delete, so
	# their staleness is always answerable and `$HOME` has nothing to do with it.
	# Without this case the fix above could silently disarm the whole rule.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="mise-tasks/retired-long-ago.sh CLOUD-312"
	complete_wiring
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-stale"* ]]
}

@test "CLOUD-525 (e): a declared row whose owner is a CLOSED issue is a violation" {
	# The sibling of `stale`, and the permanent-exemption shape the DECLARED
	# pattern exists to prevent: a retirement's licence outliving the row that was
	# supposed to deliver it. Agents fetch, gates decide — the board arrives on
	# stdin because no gate path has a tracker credential.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="stop-hook-git-check.sh CLOUD-605"
	complete_wiring
	with_merged Stop '~/.claude/stop-hook-git-check.sh'
	board '{"id":"CLOUD-605","statusType":"completed"}'
	run gate_with_board
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-declaration-closed-owner"* ]]
}

@test "CLOUD-525: an OPEN owner keeps the same declared row green" {
	# The discriminator for (e): without this, a check that refused every declared
	# row would pass (e) and prove nothing.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="stop-hook-git-check.sh CLOUD-605"
	complete_wiring
	with_merged Stop '~/.claude/stop-hook-git-check.sh'
	board '{"id":"CLOUD-605","statusType":"unstarted"}'
	run gate_with_board
	[ "$status" -eq 0 ]
}

@test "CLOUD-525: with no board piped in, the owner rule is unenforced rather than assumed" {
	# Could-not-look, and it must be neither a pass for the WRONG reason nor a
	# failure: the ordinary pre-commit run supplies no payload, and a gate that
	# demanded one would be red on every commit.
	MERGED="claude-code .claude/launcher-settings.json"
	DECLARED="stop-hook-git-check.sh CLOUD-605"
	complete_wiring
	with_merged Stop '~/.claude/stop-hook-git-check.sh'
	run gate
	[ "$status" -eq 0 ]
}

@test "CLOUD-525: an ABSENT merged surface is the ordinary case, not a finding" {
	# Most machines carry no launcher file. A gate red for its absence would be
	# red on every developer's box for a state nobody can fix.
	MERGED="claude-code .claude/launcher-settings.json"
	complete_wiring
	run gate
	[ "$status" -eq 0 ]
}

@test "THE SCOPE IS EVERY EVENT NOW: a Stop sibling is a violation too" {
	# The inversion CLOUD-777 argues for directly: "CLOUD-312 is titled 'the
	# engine is the pre-tool entry point'. The entry point is every point." The
	# old scope note was not wrong about its own state — it declined to price
	# retiring a recorder like retiring a decision table — and the decision
	# reprices both: nothing else registers a hook.
	with_sibling Stop '$CLAUDE_PROJECT_DIR/mise-tasks/stop-guard.sh'
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"wiring-sibling-command"* ]]
	[[ "$output" == *"stop-guard"* ]]
}
