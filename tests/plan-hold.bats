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

# --- the predicate ------------------------------------------------------------

@test "check reports not-live before anything has ever held this clone" {
	run "$CHECK" live
	[ "$status" -eq 1 ]
	# A refusal must carry its fix, and the fix must be the command, not advice.
	[[ "$output" == *"mise run plan-hold"* ]]
}

@test "check reports live for a sentinel naming a running pid" {
	mkdir -p "$(dir)"
	sleep 30 &
	local pid=$!
	printf '%s\n' "$pid" >"$(dir)/$pid"
	run "$CHECK" live
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 hold(s) live"* ]]
}

@test "a stale sentinel is not-live, and reporting it reaps it" {
	mkdir -p "$(dir)"
	# A pid that has certainly exited: spawn and reap one, then reuse its number.
	sleep 0 &
	local pid=$!
	wait "$pid" 2>/dev/null || true
	printf '%s\n' "$pid" >"$(dir)/$pid"
	run "$CHECK" live
	[ "$status" -eq 1 ]
	[ ! -e "$(dir)/$pid" ]
}

@test "a malformed sentinel is a corpse, never a hold" {
	mkdir -p "$(dir)"
	printf 'not-a-pid\n' >"$(dir)/garbage"
	: >"$(dir)/empty"
	run "$CHECK" live
	[ "$status" -eq 1 ]
	[ ! -e "$(dir)/garbage" ]
	[ ! -e "$(dir)/empty" ]
}

@test "outside a git repository the check cannot look, and says so rather than deciding" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" "$CHECK" live
	[ "$status" -eq 2 ]
}

@test "the hold directory is spelled in exactly one place" {
	run "$CHECK" dir
	[ "$status" -eq 0 ]
	[ "$output" = "$(dir)" ]
	# The other three files must ask for it rather than re-deriving it, or the
	# single spelling is a comment instead of a property.
	for f in "$HOLD" "$RELEASE" "$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-guard"; do
		! grep -q 'batten-holds' "$f"
	done
}

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

@test "a second launch while one is live is a no-op, not a second sleeper" {
	mkdir -p "$(dir)"
	sleep 30 &
	local pid=$!
	printf '%s\n' "$pid" >"$(dir)/$pid"
	run env BATTEN_PLAN_HOLD_MAX=60 "$HOLD"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"already held"* ]]
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
