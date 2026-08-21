#!/usr/bin/env bats
# subject: mise-tasks/singleton
# singleton: one <task> per clone (CLOUD-428). Measured 2026-08-12 — three
# concurrent `land` processes on one branch and two lease heartbeats, running
# against each other for ~30 minutes, because the landing lease is re-entrant
# per clone by design and therefore structurally blind to this.
#
# The rows below are the ones that incident turned on: a live holder refuses, a
# dead one is reclaimed rather than waited out, an EMPTY pid file reads as HELD,
# and the refusal names the pid rather than saying "already running".

setup() {
	SINGLE="$BATS_TEST_DIRNAME/../mise-tasks/singleton"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || exit 1
	git init -q .
	LOCK="$REPO/.git/batten-singleton/land"
}

# A live process to name as a holder. Both redirections matter: without
# >/dev/null the child inherits a command substitution's pipe and blocks it for
# its whole lifetime, and without 3>&- it holds bats' TAP stream and wedges the
# gate (CLOUD-434).
live_pid() {
	sleep 30 >/dev/null 2>&1 3>&- &
	echo $!
}

dead_pid() {
	local corpse
	(exit 0) >/dev/null 2>&1 3>&- &
	corpse=$!
	wait "$corpse" 2>/dev/null || true
	echo "$corpse"
}

hold_lock() { # <pid>
	mkdir -p "$LOCK"
	printf '%s\n' "$1" >"$LOCK/pid"
}

@test "an unheld task is acquired, and the pid file names the caller" {
	run "$SINGLE" acquire land 4242
	[ "$status" -eq 0 ]
	[ "$(cat "$LOCK/pid")" = 4242 ]
}

@test "THE ACCEPTANCE CASE: a second acquire is refused while the first is alive, and names the live pid" {
	pid=$(live_pid)
	hold_lock "$pid"
	run "$SINGLE" acquire land 4242
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"already running in this clone as pid $pid"* ]]
	# The holder's pid file is untouched: a refused caller must not disturb the
	# lock it lost.
	[ "$(cat "$LOCK/pid")" = "$pid" ]
}

@test "the refusal names the holder's phase when the registry knows it" {
	# CLOUD-425's registry is the FIRST consumer here, and strictly for the
	# message — see the next test for why it can never change the verdict.
	pid=$(live_pid)
	hold_lock "$pid"
	mkdir -p "$REPO/.git/batten-tasks"
	printf 'task: land\npid: %s\nphase: ci-wait(lap 3)\n' "$pid" >"$REPO/.git/batten-tasks/$pid"
	run "$SINGLE" acquire land 4242
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci-wait(lap 3)"* ]]
}

@test "a missing registry entry still refuses — the lock is the authority, not the registry" {
	# The registry is best-effort and can be absent, unwritable, or stale. If its
	# absence softened this to a pass, the guard would fail open in exactly the
	# conditions that produce the bug.
	pid=$(live_pid)
	hold_lock "$pid"
	run "$SINGLE" acquire land 4242
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"as pid $pid"* ]]
}

@test "a lock whose holder is dead is reclaimed, not waited out" {
	corpse=$(dead_pid)
	hold_lock "$corpse"
	run "$SINGLE" acquire land 4242
	[ "$status" -eq 0 ]
	[[ "$output" == *"reclaimed land from dead pid $corpse"* ]]
	[ "$(cat "$LOCK/pid")" = 4242 ]
}

@test "AN EMPTY PID FILE IS HELD, NEVER FREE — absence of evidence is not evidence" {
	# The holder caught between its mkdir and its write. Treating this as free is
	# how two processes both believe they won.
	mkdir -p "$LOCK"
	: >"$LOCK/pid"
	run "$SINGLE" acquire land 4242
	[ "$status" -eq 1 ]
	[[ "$output" == *"already running in this clone"* ]]
}

@test "a lock directory with no pid file at all is held too" {
	mkdir -p "$LOCK"
	run "$SINGLE" acquire land 4242
	[ "$status" -eq 1 ]
}

@test "THE PROPERTY: a killed holder does not block the next run indefinitely" {
	# The incident's own shape — the harness's stop kills the wrapper and leaves
	# the tree, so a SIGKILLed land can leave this lock behind. It must cost a
	# reclaim, never a permanent wedge.
	pid=$(live_pid)
	hold_lock "$pid"
	kill -9 "$pid" 2>/dev/null || true
	# SIGKILL is delivered asynchronously, and the process lingers until it is
	# reaped — by init here, since its parent subshell has already exited, so
	# this shell cannot `wait` for it. Poll for its actual disappearance instead
	# of assuming the kill took effect, or the row races the scheduler.
	deadline=$((SECONDS + 5))
	while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.1
	done
	! kill -0 "$pid" 2>/dev/null
	run "$SINGLE" acquire land 4242
	[ "$status" -eq 0 ]
	[ "$(cat "$LOCK/pid")" = 4242 ]
}

@test "TWO SIGHTINGS: a lock that changed hands under the reclaim is not stolen" {
	# The reason reclaim needs a second look rather than acting on the first
	# dead sighting. Between reading a corpse's pid and deciding to reclaim, the
	# corpse's own trap can remove the directory and a NEW holder can take it —
	# and reclaiming then deletes a live process's lock, producing exactly the
	# two-lands-both-believing-they-won state this task exists to prevent.
	#
	# Driven with a wide margin rather than by racing the production 0.1s
	# window: the recheck is stretched to 2s and the handover happens at ~0.3s,
	# so the row asserts an ORDERING, not a scheduler outcome.
	corpse=$(dead_pid)
	hold_lock "$corpse"
	newpid=$(live_pid)
	(
		sleep 0.3
		printf '%s\n' "$newpid" >"$LOCK/pid"
	) >/dev/null 2>&1 3>&- &
	handover=$!
	run env SINGLETON_RECHECK=2 "$SINGLE" acquire land 4242
	wait "$handover" 2>/dev/null || true
	kill "$newpid" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"as pid $newpid"* ]]
	# The new holder still has its lock.
	[ "$(cat "$LOCK/pid")" = "$newpid" ]
}

@test "release frees the lock for the next caller" {
	"$SINGLE" acquire land 4242
	run "$SINGLE" release land
	[ "$status" -eq 0 ]
	[ ! -e "$LOCK" ]
	run "$SINGLE" acquire land 5353
	[ "$status" -eq 0 ]
}

@test "release of a lock that was never taken is a no-op, not a failure" {
	# It runs from an EXIT trap that fires on paths where the acquire never
	# happened; a trap that can fail masks the real exit code.
	run "$SINGLE" release land
	[ "$status" -eq 0 ]
}

@test "tasks are locked independently — a held land does not block another task" {
	pid=$(live_pid)
	hold_lock "$pid"
	run "$SINGLE" acquire verify 4242
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
}

@test "an unknown verb is exit 2, never a silent success" {
	run "$SINGLE" grab land 4242
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage: singleton"* ]]
}

@test "acquire without a pid is exit 2, and takes no lock" {
	run "$SINGLE" acquire land
	[ "$status" -eq 2 ]
	[ ! -e "$LOCK" ]
}

@test "outside a git repository it exits 2 — could not look is not 'nothing is running'" {
	cd "$BATS_TEST_TMPDIR" || exit 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" "$SINGLE" acquire land 4242
	[ "$status" -eq 2 ]
	[[ "$output" == *"not a git repository"* ]]
}

@test "the refusal is pointer-only — a pid and a phase, never a log line" {
	pid=$(live_pid)
	hold_lock "$pid"
	printf 'error: a distinctive line no refusal may echo\n' >"$REPO/land.log"
	run "$SINGLE" acquire land 4242
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" != *"distinctive line"* ]]
}

@test "the lock is taken with mkdir, not flock — util-linux is absent on macOS" {
	# CLOUD-286's lesson, and the reason target-ensure uses this idiom at all.
	# Asserted structurally so a rewrite cannot quietly reintroduce the
	# dependency that made `verify` unrunnable on a developer's machine.
	run bash -c 'grep -vE "^[[:space:]]*#" "$1" | grep -c "\bflock\b" || true' _ "$SINGLE"
	[ "$output" = 0 ]
	grep -q 'mkdir "$lock" 2>/dev/null' "$SINGLE"
}
