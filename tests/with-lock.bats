#!/usr/bin/env bats
# subject: mise-tasks/with-lock.sh
# The mutual-exclusion primitive itself (CLOUD-201), extracted from
# `target-ensure` so `doctor` could hold the same kind of lock without a second
# copy of its edge cases. Those edges are the whole reason it has a suite: a
# lock that never blocks, never releases, or swallows the verdict of what it
# guards all look identical from the outside on a quiet machine.
#
# `tests/target-race.bats` and `tests/target-ensure.bats` remain the proof that
# the extraction preserved behaviour at the call site; this suite is about the
# primitive alone.

setup() {
	WITH_LOCK="$BATS_TEST_DIRNAME/../mise-tasks/with-lock.sh"
	LOCK="$BATS_TEST_TMPDIR/lock"
	LOG="$BATS_TEST_TMPDIR/log"
}

@test "the wrapped command runs, and its stdout is untouched by the lock" {
	run "$WITH_LOCK" "$LOCK" -- echo hello
	[ "$status" -eq 0 ]
	[ "$output" = "hello" ]
}

@test "THE VERDICT SURVIVES: a failing command's exit status is the task's" {
	# A lock wrapper that reported its own success would destroy the verdict of
	# everything it guards — the defect `run-shape-guard` denies at the call
	# site, one level down where no shape check can see it.
	run "$WITH_LOCK" "$LOCK" -- bash -c 'exit 7'
	[ "$status" -eq 7 ]
}

@test "the lock is released on success" {
	run "$WITH_LOCK" "$LOCK" -- true
	[ "$status" -eq 0 ]
	[ ! -e "$LOCK" ]
}

@test "the lock is released when the wrapped command FAILS" {
	# The half that matters: a failure that leaves the lock held wedges every
	# later caller for the full timeout, turning one red run into a stuck repo.
	run "$WITH_LOCK" "$LOCK" -- false
	[ "$status" -eq 1 ]
	[ ! -e "$LOCK" ]
}

@test "a second caller waits for the holder rather than running concurrently" {
	"$WITH_LOCK" "$LOCK" -- bash -c "echo A-start >>'$LOG'; sleep 0.5; echo A-end >>'$LOG'" &
	local first=$!
	local i
	for i in $(seq 1 100); do
		[ -e "$LOCK/pid" ] && break
		sleep 0.02
	done
	"$WITH_LOCK" "$LOCK" -- bash -c "echo B >>'$LOG'"
	wait "$first"
	# B cannot appear between A's two lines: that ordering IS the exclusion.
	[ "$(cat "$LOG")" = "$(printf 'A-start\nA-end\nB')" ]
}

@test "a held lock past the timeout is a loud failure, not a hang" {
	mkdir -p "$LOCK"
	echo $$ >"$LOCK/pid"
	run env WITH_LOCK_TIMEOUT=1 "$WITH_LOCK" "$LOCK" -- true
	[ "$status" -eq 1 ]
	[[ "$output" == *"timed out"* ]]
}

@test "the caller names what the wait was for, so the pointer is the concept" {
	mkdir -p "$LOCK"
	echo $$ >"$LOCK/pid"
	run env WITH_LOCK_TIMEOUT=1 WITH_LOCK_LABEL="the toolchain lock (some-triple)" \
		"$WITH_LOCK" "$LOCK" -- true
	[ "$status" -eq 1 ]
	[[ "$output" == *"the toolchain lock (some-triple)"* ]]
}

@test "a lock whose holder is dead is reclaimed, not waited out" {
	# A directory lock's release comes from the trap, which a SIGKILLed holder
	# never runs. Reclaim is what keeps that a delay of one poll instead of the
	# full timeout — a timeout here means it regressed.
	(exit 0) &
	local corpse=$!
	wait "$corpse" 2>/dev/null || true
	mkdir -p "$LOCK"
	echo "$corpse" >"$LOCK/pid"
	run env WITH_LOCK_TIMEOUT=5 "$WITH_LOCK" "$LOCK" -- echo through
	[ "$status" -eq 0 ]
	[ "$output" = "through" ]
}

@test "an EMPTY pid file is a holder mid-write, never a corpse" {
	# Absence of evidence is "held": a holder caught between its mkdir and its
	# write must not be reclaimed out from under itself.
	mkdir -p "$LOCK"
	: >"$LOCK/pid"
	run env WITH_LOCK_TIMEOUT=1 "$WITH_LOCK" "$LOCK" -- true
	[ "$status" -eq 1 ]
	[[ "$output" == *"timed out"* ]]
}

@test "the pre-CLOUD-286 lock FILE does not wedge the directory lock" {
	# Every machine that ran doctor before CLOUD-286 has a regular file at its
	# lock path. mkdir can never succeed against it, so an unhandled one is a
	# full timeout on the first run after upgrading, on every existing checkout.
	: >"$LOCK"
	run env WITH_LOCK_TIMEOUT=5 "$WITH_LOCK" "$LOCK" -- echo through
	[ "$status" -eq 0 ]
	[ "$output" = "through" ]
}

@test "a missing parent directory is created rather than refused" {
	run "$WITH_LOCK" "$BATS_TEST_TMPDIR/nested/deeper/lock" -- echo through
	[ "$status" -eq 0 ]
	[ "$output" = "through" ]
}

@test "a malformed invocation refuses instead of running something unlocked" {
	run "$WITH_LOCK" "$LOCK" echo hello
	[ "$status" -eq 1 ]
	[[ "$output" == *"expected"* ]]
	[ ! -e "$LOCK" ]
}

@test "no command after the separator is a refusal, not a silent lock-and-exit" {
	run "$WITH_LOCK" "$LOCK" --
	[ "$status" -eq 1 ]
	[[ "$output" == *"no command"* ]]
}
