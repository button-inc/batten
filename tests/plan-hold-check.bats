#!/usr/bin/env bats
# The hold's PREDICATES — both of them. `live` answers about now; `spanned`
# answers about the last container replacement (CLOUD-491).
#
# Split from `tests/plan-hold.bats`, which keeps the sleeper and the release.
# Two reasons, and the second is the enforceable one. The check is a pure
# function of filesystem state and deserves its own decision table, the way
# `claim-check`, `land-lock-check` and `stop-posture-check` each have one and
# this task alone did not. And `mise run mutant` derives its suite as
# `tests/$gate.bats`, so a predicate tested inside another task's file cannot be
# mutation-checked at all — the rows below would have been coverage nobody could
# prove discriminates.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the paths are resolved from `git rev-parse --absolute-git-dir`, so a suite
# running in this repo's own checkout would arm and reap holds — and rewrite the
# heartbeat — in the working clone while a session might be relying on one.
#
# BOOT TIME IS INJECTED, never read. `/proc/stat` cannot be faked, and without
# `BATTEN_BOOT_TIME` not one row below could vary the thing the predicate turns
# on; the suite would pass in every direction and prove nothing (CLOUD-418).

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-check"
	HOLD="$BATS_TEST_DIRNAME/../mise-tasks/plan-hold"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	cd "$REPO" || return 1
	export BATTEN_PLAN_HOLD_POLL=1
	# A fixed, obviously-synthetic boot time. Every row states its own relation
	# to this number rather than inheriting one.
	NOW=1000000
	export BATTEN_BOOT_TIME="$NOW"
}

teardown() {
	# Never leave a sleeper behind: a capped-at-4-hours hold from a failed test
	# would outlive the suite and hold a CI runner open.
	[ -n "${REPO:-}" ] && [ -d "$REPO/.git/batten-holds" ] &&
		rm -f "$REPO"/.git/batten-holds/* 2>/dev/null
	wait 2>/dev/null || true
}

dir() { printf '%s\n' "$(git -C "$REPO" rev-parse --absolute-git-dir)/batten-holds"; }
beat() { printf '%s\n' "$(git -C "$REPO" rev-parse --absolute-git-dir)/batten-hold-heartbeat"; }
boots() { printf '%s\n' "$(git -C "$REPO" rev-parse --absolute-git-dir)/batten-boots"; }

# --- is a hold live right now? ------------------------------------------------

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

# --- the verb table -----------------------------------------------------------

@test "an unknown verb cannot look, and names the ones that exist" {
	run "$CHECK" definitely-not-a-verb
	[ "$status" -eq 2 ]
	[[ "$output" == *"unknown mode"* ]]
	# The refusal carries the list, so a caller is not sent to read the source.
	[[ "$output" == *"spanned"* ]]
}

@test "the paths are spelled in exactly one place" {
	run "$CHECK" dir
	[ "$status" -eq 0 ]
	[ "$output" = "$(dir)" ]
	run "$CHECK" heartbeat-path
	[ "$status" -eq 0 ]
	[ "$output" = "$(beat)" ]
	# The callers must ASK for these rather than re-deriving them, or the single
	# spelling is a comment instead of a property. Code only: a header may name a
	# path while explaining why it does not re-derive it.
	local f
	for f in "$HOLD" "$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release" \
		"$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-release-tool" \
		"$BATS_TEST_DIRNAME/../mise-tasks/plan-hold-guard"; do
		run bash -c "grep -vE '^[[:space:]]*#' '$f' | grep -cE 'batten-holds|batten-hold-heartbeat|batten-boots'"
		[ "$output" -eq 0 ]
	done
}

@test "the poll interval has one home, and the hold takes it from here" {
	run env -u BATTEN_PLAN_HOLD_POLL "$CHECK" poll
	[ "$status" -eq 0 ]
	[ "$output" = "5" ]
	# The sleeper must not carry a second default: two literals that must agree
	# drift silently, and the disagreement would be the reader reasoning about a
	# rate the sleeper is not polling at.
	run bash -c "grep -vE '^[[:space:]]*#' '$HOLD' | grep -c 'BATTEN_PLAN_HOLD_POLL'"
	[ "$output" -eq 0 ]
}

# --- did a hold span the last container replacement? --------------------------
#
# THE MEASURED CONSTRAINT behind every row here (CLOUD-491): the last 182 s of
# writes before a container replacement were measured not to survive. So the
# predicate must NOT be "how recent is the last beat" — that reading is minutes
# stale exactly when it is asked. It is the last record's KIND instead: `x` is
# written only where the hold chose to stop, so an `h` in final position is a
# hold that never got to choose.

@test "an h left by a previous boot means a hold was live when the container went" {
	printf 'h 999000 999999\n' >"$(beat)"
	run "$CHECK" spanned
	[ "$status" -eq 0 ]
	[[ "$output" == *"was live when this container replaced"* ]]
}

@test "an x means the hold ended on purpose, however long ago" {
	local reason
	for reason in released capped; do
		printf 'h 999000 999999\nx 999001 999999 %s\n' "$reason" >"$(beat)"
		run "$CHECK" spanned
		[ "$status" -eq 1 ]
		[[ "$output" == *"ended on purpose"* ]]
	done
}

# THE ROW A CLOCK GETS WRONG, and the reason the boot time is paired into every
# record. This heartbeat is seconds old — the freshest possible — and it still
# spanned nothing, because it belongs to the boot doing the asking.
@test "a heartbeat from this very boot spanned nothing" {
	printf 'h %s %s\n' "$((NOW + 5))" "$NOW" >"$(beat)"
	run "$CHECK" spanned
	[ "$status" -eq 1 ]
	[[ "$output" == *"from this boot"* ]]
}

# THE ROW A NAIVE RECENCY TEST GETS WRONG IN THE OTHER DIRECTION. This beat is
# ancient by any clock — far more than the 182 s that were measured lost — and it
# is still the correct answer, because the hold never wrote an x.
@test "an h stays evidence however stale the clock says it is" {
	printf 'h 1 2\n' >"$(beat)"
	run "$CHECK" spanned
	[ "$status" -eq 0 ]
}

@test "no heartbeat but a prior boot recorded means no hold was ever armed here" {
	printf '999999\n%s\n' "$NOW" >"$(boots)"
	run "$CHECK" spanned
	[ "$status" -eq 1 ]
	[[ "$output" == *"ever been armed"* ]]
}

# THE CASE THAT MUST NOT BECOME A VERDICT. A fresh disk carries no evidence
# either way, and answering "no hold was live" there is the claim that licenses
# the idle handoff this whole mechanism exists to refuse.
@test "no heartbeat and no prior boot cannot look, rather than deciding" {
	run "$CHECK" spanned
	[ "$status" -eq 2 ]
	printf '%s\n' "$NOW" >"$(boots)"
	run "$CHECK" spanned
	[ "$status" -eq 2 ]
}

@test "an empty or unreadable heartbeat never reads as spanned" {
	: >"$(beat)"
	printf '999999\n' >"$(boots)"
	run "$CHECK" spanned
	[ "$status" -eq 1 ]

	printf 'garbage\n' >"$(beat)"
	run "$CHECK" spanned
	[ "$status" -eq 2 ]

	printf 'h not-a-number %s\n' "$NOW" >"$(beat)"
	run "$CHECK" spanned
	[ "$status" -eq 2 ]
}

@test "an unreadable boot source cannot look" {
	printf 'h 999000 999999\n' >"$(beat)"
	# A present override is authoritative, so a malformed one is the unreadable
	# case rather than a silent fall-through to /proc/stat — which is the only
	# way a suite can exercise this branch at all, since /proc/stat always reads
	# on the machines this runs on.
	local bad
	for bad in "" "not-a-number" "12x"; do
		run env BATTEN_BOOT_TIME="$bad" "$CHECK" spanned
		[ "$status" -eq 2 ]
		run env BATTEN_BOOT_TIME="$bad" "$CHECK" boot
		[ "$status" -eq 2 ]
	done
}

# --- the sensor must not be eaten by the mechanism ----------------------------
#
# The first draft of CLOUD-491 filed the heartbeat inside the hold directory.
# Both reaping loops delete every file there whose first line is not a pid, so
# the check would have destroyed the record it exists to read, on its first call.
@test "reading liveness does not delete the heartbeat" {
	mkdir -p "$(dir)"
	printf 'h 999000 999999\n' >"$(beat)"
	printf 'not-a-pid\n' >"$(dir)/garbage"
	run "$CHECK" live
	[ "$status" -eq 1 ]
	[ ! -e "$(dir)/garbage" ]
	[ -s "$(beat)" ]
	run "$CHECK" spanned
	[ "$status" -eq 0 ]
}

# --- recording the boot -------------------------------------------------------

@test "a boot is recorded once, however many sessions start in it" {
	run "$CHECK" record-boot
	[ "$status" -eq 0 ]
	run "$CHECK" record-boot
	[ "$status" -eq 0 ]
	run bash -c "wc -l < '$(boots)'"
	[ "$output" -eq 1 ]
	# A later boot appends rather than replacing: the earlier one is the evidence
	# that this disk predates it.
	run env BATTEN_BOOT_TIME=$((NOW + 500)) "$CHECK" record-boot
	[ "$status" -eq 0 ]
	run bash -c "wc -l < '$(boots)'"
	[ "$output" -eq 2 ]
}
