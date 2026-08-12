#!/usr/bin/env bats
# task-registry: the writer half of CLOUD-425. These tests pin the record — the
# fields, the atomic rewrite, and the two degradations that matter: a phase
# update for a task that never registered must not fabricate one, and an
# unwritable registry must not fail the caller. `alive` is the reader and has
# its own suite; the distinction between "nothing runs" and "could not look"
# lives there, because it is a property of the answer rather than the record.

setup() {
	REG="$BATS_TEST_DIRNAME/../mise-tasks/task-registry"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || exit 1
	git init -q .
	ENTRIES="$REPO/.git/batten-tasks"
}

field() { # <pid> <name>
	sed -n "s/^$2: //p" "$ENTRIES/$1" 2>/dev/null | head -n 1
}

@test "register writes one entry per pid, carrying task, pid, pgid and a start time" {
	run "$REG" register land 4242 starting
	[ "$status" -eq 0 ]
	[ -f "$ENTRIES/4242" ]
	[ "$(field 4242 task)" = land ]
	[ "$(field 4242 pid)" = 4242 ]
	[ "$(field 4242 phase)" = starting ]
	# pgid is recorded because `set -m` puts each task's tree in its own group;
	# an unreadable one falls back to the pid, so it is never empty.
	[ -n "$(field 4242 pgid)" ]
	# A start time the reader can turn into an age, not a formatted date.
	[[ "$(field 4242 started_at)" =~ ^[0-9]+$ ]]
}

@test "register defaults the phase rather than writing an empty one" {
	run "$REG" register land 4242
	[ "$status" -eq 0 ]
	[ "$(field 4242 phase)" = starting ]
}

@test "phase rewrites only the phase, preserving task and start time" {
	"$REG" register land 4242 starting
	before_start="$(field 4242 started_at)"
	run "$REG" phase 4242 "verify(lap 1)"
	[ "$status" -eq 0 ]
	[ "$(field 4242 phase)" = "verify(lap 1)" ]
	[ "$(field 4242 task)" = land ]
	[ "$(field 4242 started_at)" = "$before_start" ]
}

@test "a phase update for a pid that never registered fabricates nothing" {
	# The registry records what registered. Inventing an entry here would let a
	# half-wired task look fully wired, which is the failure mode this whole
	# issue is about: a confident answer with nothing behind it.
	run "$REG" phase 9999 verify
	[ "$status" -eq 0 ]
	[ ! -e "$ENTRIES/9999" ]
}

@test "unregister removes the entry" {
	"$REG" register land 4242 starting
	run "$REG" unregister 4242
	[ "$status" -eq 0 ]
	[ ! -e "$ENTRIES/4242" ]
}

@test "unregister of an absent entry is a no-op, not a failure" {
	# It runs from an EXIT trap, which fires on paths where registration never
	# happened. A trap that can fail is a trap that masks the real exit code.
	run "$REG" unregister 9999
	[ "$status" -eq 0 ]
}

@test "an unwritable registry degrades to a no-op rather than failing the caller" {
	# A land must never die because its own bookkeeping could not be written.
	#
	# Blocked by putting a FILE where the registry directory belongs, not by
	# clearing permission bits: this suite runs as root in CI and in the sandbox,
	# and root is not subject to the bits, so a chmod-based version would pass
	# because the write SUCCEEDED — a green test asserting the opposite of what
	# it claims.
	printf 'not a directory\n' >"$ENTRIES"
	run "$REG" register land 4242 starting
	[ "$status" -eq 0 ]
	[ ! -e "$ENTRIES/4242" ]
}

@test "an entry is never observed half-written" {
	# Rewrite-and-rename, so a reader either sees the old record or the new one.
	# Asserted structurally: the writer must not redirect onto the live path.
	! grep -qE '>"\$file"' "$REG"
	grep -q 'mv -f "$tmp" "$file"' "$REG"
}

@test "an unknown verb is exit 2, never a silent success" {
	run "$REG" sniff 4242
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage: task-registry"* ]]
}

@test "register without a pid is exit 2, never a partial record" {
	run "$REG" register land
	[ "$status" -eq 2 ]
	[ ! -d "$ENTRIES" ] || [ -z "$(ls -A "$ENTRIES")" ]
}

@test "phase without a phase word is exit 2" {
	run "$REG" phase 4242
	[ "$status" -eq 2 ]
}

@test "outside a git repository it exits 2 — there is nowhere to record" {
	cd "$BATS_TEST_TMPDIR" || exit 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" "$REG" register land 4242
	[ "$status" -eq 2 ]
	[[ "$output" == *"not a git repository"* ]]
}

@test "this task never sends a signal" {
	# CLOUD-425's safety property, held structurally rather than by check.
	# SIGUSR1's default disposition is Term: a registry that signalled would
	# kill the work it was meant to describe. `kill -0` is a permission probe
	# and sends nothing, so it is the only form allowed anywhere in this layer.
	#
	# Comment lines are stripped first — the header discusses kill(2) and
	# SIGUSR1 at length, and a property test that a rewrite of the PROSE can
	# fail is a false positive waiting to be bypassed.
	run bash -c '
		grep -vE "^[[:space:]]*#" "$1" |
			grep -oE "\bkill\b[^|;)&]*" |
			grep -vE "^kill -0\b" || true
	' _ "$REG"
	[ -z "$output" ]
}
