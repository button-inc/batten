#!/usr/bin/env bats
# subject: mise-tasks/alive
# alive: the reader half of CLOUD-425. The decision table below is the whole
# point of the issue — a backgrounded task's state was previously knowable only
# by reading its log and running `pgrep`, which on 2026-08-12 reported a dead
# `land` as "still in verify" twice, seventeen minutes apart.
#
# Three answers must stay distinct, and conflating any two is the defect:
#   running   — registered, and the process is still that task
#   crashed   — registered, and the process is gone (a STATE, not an absence)
#   nothing   — nothing registered, which is not the same as could-not-look (2)

setup() {
	ALIVE="$BATS_TEST_DIRNAME/../mise-tasks/alive"
	REG="$BATS_TEST_DIRNAME/../mise-tasks/task-registry"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || exit 1
	git init -q .
	ENTRIES="$REPO/.git/batten-tasks"
	# The liveness probe corroborates that a live pid is still the task that
	# registered it (pids recycle — CLOUD-432), by matching `/mise-tasks/<task>`
	# in the process's own cmdline. So a fixture "task" has to live at a path of
	# that shape to be recognisable; a bare `sleep` deliberately is not.
	FAKE="$BATS_TEST_TMPDIR/mise-tasks"
	mkdir -p "$FAKE"
	# Deliberately NOT `exec sleep`: exec replaces the process image, so the
	# cmdline would become `sleep 30` and the corroboration would correctly
	# refuse to call it faketask. The fixture has to stay the task it claims.
	printf '#!/usr/bin/env bash\nsleep "$1"\n' >"$FAKE/faketask"
	printf '#!/usr/bin/env bash\nsleep "$1"\n' >"$FAKE/othertask"
	chmod +x "$FAKE/faketask" "$FAKE/othertask"
}

# A live process that a probe will accept as <task>. Returns its pid.
#
# Both redirections are load-bearing, and each cost a wedged run to find:
#
#   >/dev/null — without it the child inherits this function's stdout, which
#   under `pid=$(start_task ...)` is the command substitution's pipe. Bash reads
#   that pipe until EOF, so the assignment would block for the child's whole
#   lifetime and the "background" process would not be one.
#
#   3>&- — bats' TAP stream is fd 3, and a descendant holding it wedges the
#   entire gate: bats waits for EOF on an fd the orphan still has open, and the
#   suite hangs green (CLOUD-434). Same reason tests/land.bats wraps the task
#   under test in an fd-closing shim.
start_task() { # <task> <seconds>
	"$FAKE/$1" "$2" >/dev/null 2>&1 3>&- &
	echo $!
}

# A pid that is certainly gone. The idiom tests/target-ensure.bats already uses
# for a dead lock holder: reap it so the kernel is not still holding a zombie.
dead_pid() {
	local corpse
	(exit 0) >/dev/null 2>&1 3>&- &
	corpse=$!
	wait "$corpse" 2>/dev/null || true
	echo "$corpse"
}

@test "nothing registered is a real answer, and exit 0" {
	run "$ALIVE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing registered"* ]]
}

@test "a registry that exists but is empty still reports nothing registered" {
	mkdir -p "$ENTRIES"
	run "$ALIVE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing registered"* ]]
}

@test "a running task reports its task, phase, pid and age" {
	pid=$(start_task faketask 30)
	"$REG" register faketask "$pid" "verify(lap 1)"
	run "$ALIVE"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"faketask verify(lap 1) $pid "* ]]
	[[ "$output" == *"s"* ]]
	[[ "$output" != *crashed* ]]
}

@test "a line says how long the task has been in its phase, not only how long it has run" {
	# CLOUD-499. The total age cannot separate a land working from a land stuck —
	# both grow at one second per second. The phase age is the number that can,
	# and it is what makes a stall readable here rather than in a log.
	pid=$(start_task faketask 30)
	"$REG" register faketask "$pid" "ci-wait(lap 1)"
	run "$ALIVE"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"in-phase "*"s"* ]]
}

@test "an entry written before the phase stamp existed still renders" {
	# The rollout row: a registry entry from a running task that predates this
	# field must not become an unrenderable record halfway through a landing.
	pid=$(start_task faketask 30)
	"$REG" register faketask "$pid" "ci-wait(lap 1)"
	grep -v '^phase_since: ' "$ENTRIES/$pid" >"$ENTRIES/$pid.tmp"
	mv "$ENTRIES/$pid.tmp" "$ENTRIES/$pid"
	run "$ALIVE"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"faketask ci-wait(lap 1) $pid "* ]]
	[[ "$output" != *"in-phase"* ]]
}

@test "N running tasks report one line each" {
	a=$(start_task faketask 30)
	b=$(start_task othertask 30)
	"$REG" register faketask "$a" verify
	"$REG" register othertask "$b" ci-wait
	run "$ALIVE"
	kill "$a" "$b" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[ "${#lines[@]}" -eq 2 ]
	[[ "$output" == *"faketask verify $a "* ]]
	[[ "$output" == *"othertask ci-wait $b "* ]]
}

@test "THE ACCEPTANCE CASE: an entry whose pid is gone reports crashed, and is reaped" {
	# Not "running", and not absent. The last phase survives into the crash line
	# because died-in-verify and died-in-ci-wait are different diagnoses, and
	# recovering that was most of what the seventeen minutes were spent on.
	corpse=$(dead_pid)
	"$REG" register land "$corpse" "ci-wait(lap 3)"
	run "$ALIVE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"land crashed(ci-wait(lap 3)) $corpse "* ]]
	# Reaped: reporting a headstone once is a diagnosis, reporting it forever is
	# a registry that fills with corpses and stops being read.
	[ ! -e "$ENTRIES/$corpse" ]
	run "$ALIVE"
	[[ "$output" == *"nothing registered"* ]]
}

@test "a live pid that is no longer the task that registered it reports crashed" {
	# The pid-recycle case (CLOUD-432): this clone measurably wrapped its pid
	# space inside 20 minutes. Existence alone would call a stranger's process
	# our task, which is how a wedged lease survives unnoticed.
	sleep 30 >/dev/null 2>&1 3>&- &
	stranger=$!
	"$REG" register land "$stranger" verify
	run "$ALIVE"
	kill "$stranger" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"land crashed(verify) $stranger "* ]]
}

@test "a task that never registered is invisible, never assumed dead" {
	pid=$(start_task faketask 30)
	run "$ALIVE"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing registered"* ]]
	[[ "$output" != *crashed* ]]
}

@test "a registry that is not a directory is exit 2 — could not look is not 'nothing runs'" {
	# The distinction the whole issue turns on. A reader that answered "nothing
	# is running" because it could not open the registry would be exactly the
	# confident-but-empty answer that made a dead land look alive.
	#
	# Driven by putting a FILE in the registry's place rather than by clearing
	# its permission bits, because this suite runs as root in CI and in the
	# sandbox, and root is not subject to the bits — a chmod-based version of
	# this test passes for the wrong reason there, which is worse than absent.
	printf 'not a directory\n' >"$ENTRIES"
	run "$ALIVE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot say what is running"* ]]
	[[ "$output" != *"nothing registered"* ]]
}

@test "an unreadable registry directory is exit 2" {
	[ "$(id -u)" -ne 0 ] || skip "root is not subject to the permission bits"
	mkdir -p "$ENTRIES"
	chmod 000 "$ENTRIES"
	run "$ALIVE"
	chmod 755 "$ENTRIES"
	[ "$status" -eq 2 ]
	[[ "$output" != *"nothing registered"* ]]
}

@test "outside a git repository it exits 2 rather than claiming nothing runs" {
	cd "$BATS_TEST_TMPDIR" || exit 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" "$ALIVE"
	[ "$status" -eq 2 ]
	[[ "$output" != *"nothing registered"* ]]
}

@test "a half-written entry is skipped, not rendered as a line of blanks" {
	mkdir -p "$ENTRIES"
	printf 'phase: verify\n' >"$ENTRIES/4242"
	run "$ALIVE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing registered"* ]]
}

@test "output is byte-stable across runs for the same registry state" {
	a=$(start_task faketask 30)
	b=$(start_task othertask 30)
	"$REG" register faketask "$a" verify
	"$REG" register othertask "$b" ci-wait
	first=$("$ALIVE")
	second=$("$ALIVE")
	kill "$a" "$b" 2>/dev/null || true
	# Ages can tick between the two reads; the SHAPE and ORDER may not.
	[ "$(printf '%s\n' "$first" | cut -d' ' -f1-3)" = \
		"$(printf '%s\n' "$second" | cut -d' ' -f1-3)" ]
}

@test "THE PROPERTY: output is a pointer — never a line of any log" {
	# Being forced to read logs is the defect; emitting log content here would
	# reintroduce it through the front door. Asserted two ways, because a
	# substring check alone would pass a reader that echoed a DIFFERENT log.
	pid=$(start_task faketask 30)
	"$REG" register faketask "$pid" verify
	printf 'error: a distinctive line no reader may echo\n' >"$REPO/land.log"
	run "$ALIVE"
	kill "$pid" 2>/dev/null || true
	[ "$status" -eq 0 ]
	[[ "$output" != *"distinctive line"* ]]
	# Structural: every line is exactly `<task> <phase> <pid> <age>s`, with the
	# optional `in-phase <n>s` suffix CLOUD-499 added. A shape this tight cannot
	# carry a log line whatever the log happens to contain — the suffix is two
	# fixed tokens and a count, so widening the grammar by it admits no prose.
	while IFS= read -r line; do
		[[ "$line" =~ ^[^[:space:]]+\ [^[:space:]]+\ [0-9]+\ [0-9?]+s(\ in-phase\ [0-9]+s)?$ ]]
	done <<<"$output"
}

@test "THE PROPERTY: the reader never sends a signal" {
	# SIGUSR1's default disposition is Term, so a reader that signalled would
	# kill the task it came to inspect — and a bash trap cannot answer while a
	# foreground child runs anyway, which is precisely when the answer is
	# wanted. `kill -0` sends nothing and is the only permitted form.
	# Comments are stripped: the header explains SIGUSR1 at length, and a
	# property test a prose rewrite can fail is a false positive in waiting.
	run bash -c '
		grep -vE "^[[:space:]]*#" "$1" |
			grep -oE "\bkill\b[^|;)&]*" |
			grep -vE "^kill -0\b" || true
	' _ "$ALIVE"
	[ -z "$output" ]
}
