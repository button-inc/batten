#!/usr/bin/env bats
# subject: crates/batten/src/wiring.rs
#
# Paths only on that line: it is read as whitespace-separated paths, and it is
# what buys this file's deletion once they die.
#
# THE SECOND TIER for `batten wiring reclaim` (CLOUD-893). `wiring.rs`'s own unit
# cases pin `prune_siblings` against documents they build themselves, which is the
# `with input as` shape `.claude/rules/policy-modules.md` names: it fabricates the
# document the ENGINE may be unable to locate, so every one of them could pass
# over a verb that reads the wrong home directory, refuses without `-y` in the
# wrong direction, or writes the record after the repair instead of before.
#
# Those four are what this file asserts, over the compiled binary, against a real
# `$HOME` on disk.
#
# WHY A FIXTURE `$HOME` AND NOT THIS CONTAINER'S. The verb's whole subject is a
# file under the caller's home directory, and this container HAS one — with the
# two launcher-provisioned registrations CLOUD-605 owns still in it. A suite that
# drove the real one would repair the box it is measuring, exactly once, and every
# later run would assert over a state the first run destroyed. `etcetera` resolves
# from `$HOME`, so overriding it is the whole isolation.

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
	mkdir -p "$REPO"
	printf 'version = 1\n' >"$REPO/batten.toml"
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"

	# The fixture home, carrying one merged surface with one batten registration
	# and one sibling. `.claude/launcher-settings.json` is a path
	# `Harness::merge_surfaces` declares, so this is the real selection rather than
	# a name this file invented.
	HOME_DIR="$BATS_TEST_TMPDIR/home"
	mkdir -p "$HOME_DIR/.claude"
	SURFACE="$HOME_DIR/.claude/launcher-settings.json"
	cat >"$SURFACE" <<-'JSON'
		{
		  "hooks": {
		    "SessionStart": [
		      {
		        "hooks": [
		          {"type": "command", "command": "batten hook --harness claude-code"},
		          {"type": "command", "command": "/opt/launcher/session-start-git-identity.sh"}
		        ]
		      }
		    ],
		    "Stop": [
		      {"hooks": [{"type": "command", "command": "/opt/launcher/stop-hook-git-check.sh"}]}
		    ]
		  }
		}
	JSON
}

# Drive the verb with the fixture home, keeping the two streams apart: the
# arithmetic is on stderr (rule 4 — it is a count, and its subject is a filename
# off somebody's disk) and there is no stdout contract at all.
#
# The `if` is not style: bats runs each case under `set -e`, so a bare subshell
# that exits non-zero aborts the case before `$?` can be read — and every
# assertion below would then be reported as a helper failure rather than as the
# thing it was asserting.
reclaim() { # reclaim [args...]
	if (
		cd "$REPO" || exit 1
		HOME="$HOME_DIR" "$BIN" wiring reclaim "$@" \
			>"$BATS_TEST_TMPDIR/out" 2>"$BATS_TEST_TMPDIR/err"
	); then
		STATUS=0
	else
		STATUS=$?
	fi
	OUT=$(cat "$BATS_TEST_TMPDIR/out")
	ERR=$(cat "$BATS_TEST_TMPDIR/err")
}

record() { printf '%s/.git/batten-wiring/at-load.json' "$REPO"; }

@test "a destructive verb refuses without -y rather than prompting" {
	# §4's refusal, and asserted over the FILE rather than over the exit status: a
	# verb that refused and had already written is the failure that matters, and an
	# exit code alone cannot tell that apart.
	reclaim
	[ "$STATUS" -eq 1 ]
	[[ "$ERR" == *"pass -y"* ]]
	[ ! -e "$(record)" ]
	grep -q session-start-git-identity "$SURFACE"
}

@test "-n reports what would go and writes neither the file nor the record" {
	reclaim -n
	[ "$STATUS" -eq 0 ]
	[[ "$ERR" == *"would remove 2 sibling registration(s)"* ]]
	# The per-event rows, which are what make the count actionable without naming
	# a path.
	[[ "$ERR" == *"claude-code:SessionStart would remove 1"* ]]
	[[ "$ERR" == *"claude-code:Stop would remove 1"* ]]
	[ ! -e "$(record)" ]
	grep -q session-start-git-identity "$SURFACE"
	grep -q stop-hook-git-check "$SURFACE"
}

@test "THE REPAIR: the siblings go and batten's own registration stays" {
	reclaim -y
	[ "$STATUS" -eq 0 ]
	[[ "$ERR" == *"removed 2 sibling registration(s)"* ]]
	# The load-bearing positive. A `retain` on the wrong level takes batten's
	# registration out with the sibling sharing its entry, and every negative
	# assertion in this file is satisfied by that bug.
	grep -q "batten hook --harness claude-code" "$SURFACE"
	! grep -q session-start-git-identity "$SURFACE"
	! grep -q stop-hook-git-check "$SURFACE"
	# `Stop` held nothing else, so the event goes with its last entry rather than
	# surviving as an empty array no generator emits.
	run jq -r '.hooks | has("Stop")' "$SURFACE"
	[ "$output" = "false" ]
	run jq -r '.hooks.SessionStart[0].hooks | length' "$SURFACE"
	[ "$output" = "1" ]
}

@test "RECORD BEFORE REPAIR: the record carries the pre-repair count" {
	reclaim -y
	[ -e "$(record)" ]
	run jq -r '[.rows[].siblings] | add' "$(record)"
	[ "$output" = "2" ]
	# Rule 4 on the record itself. It is under `$GIT_DIR` and never committed, and
	# it still carries no path and no filename: the harness and the event are where
	# to look, and a basename would be a name off somebody's disk bought for a
	# nicer message.
	! grep -q "$HOME_DIR" "$(record)"
	! grep -q launcher "$(record)"
	! grep -q git-identity "$(record)"
	! grep -q "/" "$(record)"
}

@test "the record is written ONCE, so a second run cannot report the repair" {
	reclaim -y
	[[ "$ERR" == *"removed 2 sibling"* ]]
	# The whole ordering property. A second reclaim finds nothing — and must not
	# overwrite a record that says 2 with one that says 0, because the record
	# describes what the RUNNING session loaded and the running session has not
	# changed.
	reclaim -y
	[[ "$ERR" == *"removed 0 sibling"* ]]
	run jq -r '[.rows[].siblings] | add' "$(record)"
	[ "$output" = "2" ]
}

@test "doctor hooks reports the record beside the live count" {
	# The two numbers that must be able to disagree. Before the repair there is no
	# record — `null`, which is read-the-disk — and after it the disk says zero
	# while the record says two.
	run env HOME="$HOME_DIR" bash -c "cd '$REPO' && '$BIN' doctor hooks -J"
	[[ "$output" == *'"at_load_siblings": null'* ]]
	reclaim -y
	run env HOME="$HOME_DIR" bash -c "cd '$REPO' && '$BIN' doctor hooks -J"
	[[ "$output" == *'"at_load_siblings": 2'* ]]
	# And the live half genuinely fell, or the two numbers would agree for the
	# wrong reason.
	run env HOME="$HOME_DIR" bash -c "cd '$REPO' && '$BIN' doctor hooks -J | jq '[.harnesses[].merged_siblings] | add'"
	[ "$output" = "0" ]
}

@test "a SessionStart expires the record, which is the restart this reports" {
	reclaim -y
	[ -e "$(record)" ]
	# The one moment the disk and what a harness has loaded are the same thing, and
	# therefore the only honest place to drop the record. Driven through the real
	# hook entry point rather than by deleting the file, because what is being
	# asserted is that the engine does it.
	run env HOME="$HOME_DIR" bash -c \
		"cd '$REPO' && printf '%s' '{\"hook_event_name\":\"SessionStart\"}' | '$BIN' hook --harness claude-code"
	[ ! -e "$(record)" ]
}

@test "a merged surface that is not a wiring file is left alone, not rewritten" {
	# Could-not-look, and the direction matters: a document this verb cannot read
	# as a hook map is one it must not write back, or a repair would silently
	# reformat a file whose shape it never understood.
	printf '[]\n' >"$SURFACE"
	reclaim -y
	[ "$STATUS" -eq 0 ]
	[ "$(cat "$SURFACE")" = "[]" ]
	[[ "$ERR" == *"0 surface(s) read"* ]]
}

@test "a checkout sitting AT the home directory is never its own merged surface" {
	# The `same_file` arm, driven by the collision its comment describes: every
	# path `merge_surfaces` declares is resolved against BOTH the home directory
	# and the repository, so a checkout that sits at `$HOME` resolves each of them
	# to one file. Without the arm this verb would rewrite a version-controlled
	# file and fight `tree-clean` on every run.
	#
	# Note what that means and what this therefore asserts: the collision is TOTAL
	# here, not partial. The launcher surface deduplicates for exactly the same
	# reason the settings one does, so the honest expectation is zero surfaces read
	# and not one — the first draft of this case asserted the launcher file was
	# still reclaimed, which was a wrong premise rather than a bug.
	cp "$SURFACE" "$HOME_DIR/.claude/settings.json"
	run env HOME="$HOME_DIR" bash -c \
		"cd '$HOME_DIR' && git init -q -b main . && cp '$REPO/batten.toml' . && '$BIN' wiring reclaim -y"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 surface(s) read"* ]]
	# Untouched, both of them — which is the whole claim. That this is not simply
	# "the verb never works" is what the cases above establish, over the same
	# binary and a home directory the repository does not sit in.
	grep -q session-start-git-identity "$HOME_DIR/.claude/settings.json"
	grep -q session-start-git-identity "$SURFACE"
	grep -q stop-hook-git-check "$SURFACE"
}
