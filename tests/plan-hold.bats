#!/usr/bin/env bats
# CLOUD-451. The hold itself, its predicate, and its release.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: `plan-hold-check` resolves its sentinel directory from `git rev-parse
# --git-dir`, so a suite running in this repo's own checkout would arm and reap
# holds in the working clone while a session might be relying on one.
#
# Timing is bounded by env rather than by waiting out the defaults: the poll is
# one second and the cap is a handful, so the two properties that are genuinely
# temporal — released, capped — are provable in seconds instead of hours.

setup() {
	HOLD="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold"
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-check"
	RELEASE="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release"
	RELEASE_TOOL="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-tool"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	cd "$REPO" || return 1
	export BATTEN_PLAN_HOLD_POLL=1
}

teardown() {
	# Never leave a sleeper behind: a capped-at-4-hours hold from a failed test
	# would outlive the suite and hold a CI runner open.
	[ -n "${REPO:-}" ] && [ -d "$REPO/.git/batten-holds" ] &&
		rm -f "$REPO"/.git/batten-holds/* 2>/dev/null
	wait 2>/dev/null || true
}

dir() { printf '%s\n' "$(git -C "$REPO" rev-parse --absolute-git-dir)/batten-holds"; }

# The predicate's own rows moved to `tests/plan-hold-check.bats` (CLOUD-491) —
# the check earned its own decision table, the way `claim-check` and
# `land-lock-check` have one, and `mutant` can only reach a gate whose suite is
# named after it. What stays here is the sleeper and the release: this file's
# subject is the PROCESS, that one's is the pure function.

# --- the hold -----------------------------------------------------------------

@test "the hold arms, is visible to the check, and releases when its sentinel goes" {
	BATTEN_PLAN_HOLD_MAX=60 "$HOLD" >"$BATS_TEST_TMPDIR/hold.log" 2>&1 &
	local runner=$!

	# Wait for the sentinel rather than sleeping a guessed interval.
	local waited=0
	while ! "$CHECK" live >/dev/null 2>&1; do
		sleep 0.2
		waited=$((waited + 1))
		[ "$waited" -lt 50 ] || {
			kill "$runner" 2>/dev/null
			return 1
		}
	done

	jq -nc '{prompt: "ok, go ahead"}' | "$RELEASE"
	wait "$runner"
	[ "$?" -eq 0 ]
	grep -q 'released' "$BATS_TEST_TMPDIR/hold.log"
	# Released, not killed: the exit is the wake-up, so it must be a normal one.
	! grep -q 'capped' "$BATS_TEST_TMPDIR/hold.log"
	run "$CHECK" live
	[ "$status" -eq 1 ]
}

@test "the hold gives up at its cap rather than sleeping forever" {
	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 "$HOLD"
	[ "$status" -eq 0 ]
	[[ "$output" == *"capped"* ]]
	# And it cleans up after itself, so the next check is honest.
	run "$CHECK" live
	[ "$status" -eq 1 ]
}

# CLOUD-485 changed this property, and the replacement is strictly stronger: one
# sleeper still, but the incumbent is RELEASED rather than inherited, so every
# handoff gets the whole cap. The old behaviour handed a new handoff whatever was
# left of a previous one's window — which erodes with every handoff whose release
# never fired, and ends with a container reclaimed while somebody is reading.
@test "a second launch releases the incumbent rather than inheriting its window" {
	mkdir -p "$(dir)"
	sleep 30 &
	local pid=$!
	printf '%s\n' "$pid" >"$(dir)/$pid"
	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 "$HOLD"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"released the incumbent"* ]]
	# The incumbent's sentinel is gone, so its sleeper exits on its next poll
	# rather than being signalled — a killed hold wakes nothing.
	[ ! -e "$(dir)/$pid" ]
	# And this launch really did arm: it reached its own cap instead of returning
	# immediately, which is what proves the window is fresh rather than inherited.
	[[ "$output" == *"capped after"* ]]
}

# Still one sleeper. The stronger invariant must not have been bought by letting
# them accumulate — that was the original reason for the no-op.
@test "a second launch leaves exactly one sentinel behind, never two" {
	mkdir -p "$(dir)"
	sleep 30 &
	local pid=$!
	printf '%s\n' "$pid" >"$(dir)/$pid"
	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 "$HOLD"
	kill "$pid" 2>/dev/null || true
	# The launch capped and cleaned up after itself, so the directory is empty —
	# one sleeper existed at a time, and neither was left behind.
	run bash -c "ls -1 '$(dir)' 2>/dev/null | wc -l"
	[ "$output" -eq 0 ]
}

@test "the reported duration is wall clock, not a sum of poll intervals" {
	# Measured on a container: a hold left alone reported `capped after 14400s`
	# and had genuinely waited four hours — the number has to mean that, so a
	# short `sleep` must not be able to inflate it. POLL is deliberately larger
	# than MAX here: summing intervals would report 4, the clock reports ~2.
	local before after
	before=$(date -u +%s)
	run env BATTEN_PLAN_HOLD_MAX=2 BATTEN_PLAN_HOLD_POLL=4 "$HOLD"
	after=$(date -u +%s)
	[ "$status" -eq 0 ]
	[[ "$output" =~ capped\ after\ ([0-9]+)s ]]
	local reported="${BASH_REMATCH[1]}"
	local actual=$((after - before))
	# Within a second of the truth, in both directions.
	[ "$reported" -le $((actual + 1)) ]
	[ "$reported" -ge $((actual - 1)) ]
}

# --- what the hold RECORDS about how it stopped (CLOUD-491) --------------------
#
# These two rows are the mechanism's whole claim, and they are deliberately not
# fixtures: the distinction they assert is a property of where the writes sit in
# this file, which only a real process can demonstrate.

# THE ROW THE SENSOR EXISTS FOR. A killed hold is what a container replacement
# looks like from in here, and the evidence is that it never reached its `x`.
# This goes red the moment the `x` write is moved into the trap — which runs on
# the kill too, and would report every reclaimed hold as one that stopped on
# purpose.
@test "a killed hold leaves an h as its last record, never an x" {
	local beat
	beat=$("$CHECK" heartbeat-path)
	BATTEN_PLAN_HOLD_MAX=60 "$HOLD" >/dev/null 2>&1 &
	local runner=$!
	local waited=0
	while ! [ -s "$beat" ]; do
		sleep 0.2
		waited=$((waited + 1))
		[ "$waited" -lt 50 ] || {
			kill "$runner" 2>/dev/null
			return 1
		}
	done
	kill -9 "$runner" 2>/dev/null
	wait "$runner" 2>/dev/null || true
	run bash -c "tail -n 1 -- '$beat' | cut -d' ' -f1"
	[ "$output" = "h" ]
}

@test "a hold that stops on purpose records which way it stopped" {
	local beat
	beat=$("$CHECK" heartbeat-path)

	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 "$HOLD"
	[ "$status" -eq 0 ]
	run bash -c "tail -n 1 -- '$beat'"
	[[ "$output" == "x "*" capped" ]]

	rm -f "$beat"
	BATTEN_PLAN_HOLD_MAX=60 "$HOLD" >/dev/null 2>&1 &
	local runner=$!
	local waited=0
	while ! "$CHECK" live >/dev/null 2>&1; do
		sleep 0.2
		waited=$((waited + 1))
		[ "$waited" -lt 50 ] || {
			kill "$runner" 2>/dev/null
			return 1
		}
	done
	jq -nc '{prompt: "ok, go ahead"}' | "$RELEASE"
	wait "$runner"
	run bash -c "tail -n 1 -- '$beat'"
	[[ "$output" == "x "*" released" ]]
}

@test "every heartbeat record carries the boot it was written under" {
	local beat
	beat=$("$CHECK" heartbeat-path)
	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 BATTEN_BOOT_TIME=4242 "$HOLD"
	[ "$status" -eq 0 ]
	# Without the boot on each line, a heartbeat from THIS container cannot be
	# told from one that survived a replacement — which is the whole reading.
	run bash -c "grep -cv ' 4242' -- '$beat'"
	[ "$output" -eq 0 ]
}

@test "the hold prints nothing until it exits" {
	# The token cost of waiting is the whole reason this is a sleeper and not a
	# poller that reports. One line, at the end, is the budget.
	run env BATTEN_PLAN_HOLD_MAX=1 BATTEN_PLAN_HOLD_POLL=1 "$HOLD"
	[ "$(printf '%s\n' "$output" | grep -c .)" -eq 1 ]
}

# --- the release --------------------------------------------------------------

human() { jq -nc --arg p "${1:-please continue}" '{prompt: $p}'; }

@test "release removes every sentinel and never signals anything" {
	mkdir -p "$(dir)"
	printf '1\n' >"$(dir)/1"
	printf '2\n' >"$(dir)/2"
	run bash -c "printf '%s' '$(human)' | '$RELEASE'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	[ -z "$(ls -A "$(dir)")" ]
	# Structural, not behavioural: a release that killed would end the process
	# without the exit that carries the wake-up.
	! grep -qE '(^|[^-[:alnum:]])kill[[:space:]]' "$RELEASE"
}

@test "release is silent and successful when nothing is held" {
	run bash -c "printf '%s' '$(human)' | '$RELEASE'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- who submitted this? --------------------------------------------------------
#
# THE MEASURED DEFECT (CLOUD-451): a background task's completion notification
# arrives as a UserPromptSubmit, and the first version of this hook released on
# it — the hold reported "released after 15s" with nobody having typed. Dropping
# the door mid-sentence is the failure the hold exists to prevent, so these cases
# are the guard on the guard.

@test "a machine turn does NOT release the hold" {
	local classify="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-check"
	for envelope in \
		'<task-notification>
<task-id>abc</task-id>' \
		'<github-webhook-activity>a comment</github-webhook-activity>' \
		'<system-reminder>something changed</system-reminder>' \
		'<untrusted_external_data source="pr_comment">hi</untrusted_external_data>' \
		'[SYSTEM NOTIFICATION - NOT USER INPUT]' \
		'[Request interrupted by user for tool use]'; do
		run bash -c "jq -nc --arg p $(printf '%q' "$envelope") '{prompt: \$p}' | '$classify'"
		[ "$status" -eq 1 ]
	done
}

@test "the notification that actually broke it, end to end, leaves the hold standing" {
	mkdir -p "$(dir)"
	printf '4242\n' >"$(dir)/4242"
	run bash -c "jq -nc '{prompt: \"<task-notification>\n<task-id>b3tif110z</task-id>\n</task-notification>\"}' | '$RELEASE'"
	[ "$status" -eq 0 ]
	[ -e "$(dir)/4242" ]
}

@test "a human turn releases, including one that quotes a notification" {
	local classify="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-check"
	for said in \
		'looks good, go ahead' \
		'why did <task-notification> fire twice?' \
		'   leading whitespace is formatting, not identity'; do
		run bash -c "jq -nc --arg p $(printf '%q' "$said") '{prompt: \$p}' | '$classify'"
		[ "$status" -eq 0 ]
	done
}

@test "absence of evidence holds — an unreadable or promptless payload never releases" {
	local classify="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-check"
	for payload in 'not json' '{}' '{"prompt":""}' '{"prompt":"   "}' ''; do
		run bash -c "printf '%s' $(printf '%q' "$payload") | '$classify'"
		[ "$status" -eq 1 ]
	done
}

# --- the answer itself, not a prompt about it -----------------------------------
#
# THE MEASURED DEFECT (CLOUD-485): the guard gates `PreToolUse` on
# `ExitPlanMode|AskUserQuestion` while the release listens on
# `UserPromptSubmit`, and a human answering either of those two produces a TOOL
# RESULT rather than a prompt. So the answer was invisible to the release: a hold
# armed, an `AskUserQuestion` answered, and the hold still live afterwards, ended
# by removing its sentinel by hand.
#
# No classifier is exercised below, deliberately. The prompt path must decide
# whether a person typed; this path's provenance is structural, because the event
# fires only after a tool whose whole purpose is to ask one.

@test "answering a handoff tool releases the hold" {
	for tool in AskUserQuestion ExitPlanMode; do
		mkdir -p "$(dir)"
		printf '4242\n' >"$(dir)/4242"
		run bash -c "jq -nc --arg t '$tool' '{tool_name: \$t}' | '$RELEASE_TOOL'"
		[ "$status" -eq 0 ]
		[ ! -e "$(dir)/4242" ]
	done
}

# THE DIRECTION A SIMPLIFICATION WOULD BREAK, with nothing else going red. A
# handoff turn ends idle on purpose and the hold must outlive it — only the
# ANSWER releases. Measured in the same session: a hold that stayed live after
# `ExitPlanMode` with no reply yet was CORRECT, and a release keyed on the turn
# ending would have reintroduced the reclaim CLOUD-451 exists to prevent.
@test "a tool that is not a handoff leaves the hold standing" {
	for tool in Bash Write Edit Read; do
		mkdir -p "$(dir)"
		printf '4242\n' >"$(dir)/4242"
		run bash -c "jq -nc --arg t '$tool' '{tool_name: \$t}' | '$RELEASE_TOOL'"
		[ "$status" -eq 0 ]
		[ -e "$(dir)/4242" ]
	done
}

@test "an unreadable or nameless tool payload never releases" {
	for payload in 'not json' '{}' '{"tool_name":""}' ''; do
		mkdir -p "$(dir)"
		printf '4242\n' >"$(dir)/4242"
		run bash -c "printf '%s' $(printf '%q' "$payload") | '$RELEASE_TOOL'"
		[ "$status" -eq 0 ]
		[ -e "$(dir)/4242" ]
	done
}

@test "the tool release is silent on success" {
	mkdir -p "$(dir)"
	printf '4242\n' >"$(dir)/4242"
	run bash -c "jq -nc '{tool_name: \"AskUserQuestion\"}' | '$RELEASE_TOOL'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# The sentinel path is spelled in `plan-hold-check` and nowhere else, and this
# file must ask for it rather than re-deriving it — the same property asserted
# for the check above, now over the second releaser.
@test "the tool release derives the hold directory from the check, not from itself" {
	# Code only: the header names the path while explaining why it does not
	# re-derive it, and a prose mention is the opposite of the defect here.
	run bash -c "grep -vE '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-tool' | grep -c 'batten-holds'"
	[ "$output" -eq 0 ]
}
