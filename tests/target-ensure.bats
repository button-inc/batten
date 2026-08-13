#!/usr/bin/env bats
# target-ensure: the single locked effect through which every rustup target
# install flows (CLOUD-220). The decision half (ok/missing/stale) is
# doctor-check's and has its own suite; these tests pin the effect half — the
# lock discipline, the purge, the pointer-only failure line — against a stub
# toolchain, plus the sweep that keeps this the ONLY live `rustup target add`.

setup() {
	ENSURE="$BATS_TEST_DIRNAME/../mise-tasks/target-ensure"
	STUB="$BATS_TEST_TMPDIR/bin"
	SYSROOT="$BATS_TEST_TMPDIR/sysroot"
	STATE="$BATS_TEST_TMPDIR/state"
	mkdir -p "$STUB" "$SYSROOT/lib/rustlib" "$STATE"
	: >"$STATE/installed"

	cat >"$STUB/rustc" <<EOF
#!/usr/bin/env bash
[ "\$1" = "--print" ] && [ "\$2" = "sysroot" ] && { echo "$SYSROOT"; exit 0; }
exit 0
EOF
	cat >"$STUB/rustup" <<EOF
#!/usr/bin/env bash
STATE="$STATE"
case "\$1 \$2" in
"target list") cat "\$STATE/installed" ;;
"target add")
	echo "add \$3" >>"\$STATE/calls"
	echo "\$3" >>"\$STATE/installed" ;;
"target remove")
	echo "remove \$3" >>"\$STATE/calls"
	grep -vxF "\$3" "\$STATE/installed" >"\$STATE/i.n" || true
	mv "\$STATE/i.n" "\$STATE/installed" ;;
esac
exit 0
EOF
	chmod +x "$STUB/rustc" "$STUB/rustup"
	PATH="$STUB:$PATH"
	export PATH
	T=x86_64-pc-windows-gnu
}

@test "missing target: installs, reports the triple, exit 0" {
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"rust target $T installed"* ]]
	grep -qxF "$T" "$STATE/installed"
}

@test "already-installed target: no-op, no add call" {
	echo "$T" >>"$STATE/installed"
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"already installed"* ]]
	[ ! -e "$STATE/calls" ]
}

@test "stale residue: purged, then installed" {
	mkdir -p "$SYSROOT/lib/rustlib/$T/lib"
	echo junk >"$SYSROOT/lib/rustlib/$T/lib/libold.rlib"
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"half-installed"* ]]
	[[ "$output" == *"rust target $T installed"* ]]
	[ ! -e "$SYSROOT/lib/rustlib/$T/lib/libold.rlib" ]
	grep -qxF "$T" "$STATE/installed"
}

@test "a failing add is one ::error:: pointer line, not the rustup spew" {
	cat >"$STUB/rustup" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
"target list") exit 0 ;;
"target add")
	echo "info: downloading component 'rust-std'" >&2
	echo "info: retrying download" >&2
	echo "error: failed to install component: detected conflict" >&2
	exit 1 ;;
esac
exit 0
EOF
	chmod +x "$STUB/rustup"
	run "$ENSURE" "$T"
	[ "$status" -eq 1 ]
	[[ "$output" == *"::error:: target-ensure: could not install rust target $T"* ]]
	# Pointer-only: rustup's last line rides the pointer; the spew above it must not.
	[[ "$output" != *"downloading component"* ]]
	[[ "$output" != *"retrying download"* ]]
}

# The lock is a directory, so a test holder takes it the way target-ensure does:
# mkdir, then name a LIVE process in the pid file. A pid file naming a corpse is
# an abandoned lock by construction and would be reclaimed on sight, which would
# quietly turn the two waiting tests below into tests of nothing.
hold_lock() { # <seconds>
	mkdir -p "$SYSROOT/lib/rustlib"
	local lock="$SYSROOT/lib/rustlib/.batten-target-lock"
	# $BASHPID is the subshell's own pid, which is what $! names.
	# 3>&- on every backgrounded child (CLOUD-434): a leaked one must never
	# hold bats' TAP fd, which is how one orphan wedged the whole gate.
	{
		mkdir "$lock" && echo "$BASHPID" >"$lock/pid" && sleep "$1"
		rm -rf "$lock"
	} 3>&- &
	holder=$!
	# The holder takes the lock asynchronously; wait for its pid file so the
	# caller under test cannot win the lock before the holder has taken it.
	local i
	for i in $(seq 1 100); do
		[ -e "$lock/pid" ] && return 0
		sleep 0.02
	done
	return 1
}

@test "a queued caller waits for the lock holder, then proceeds" {
	hold_lock 0.4
	run "$ENSURE" "$T"
	wait "$holder"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
}

@test "a held lock past the timeout is a loud failure, not a hang" {
	hold_lock 5
	run env TARGET_LOCK_TIMEOUT=1 "$ENSURE" "$T"
	kill "$holder" 2>/dev/null || true
	wait "$holder" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"timed out waiting for the toolchain lock"* ]]
}

@test "the lock is released on a normal exit" {
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[ ! -e "$SYSROOT/lib/rustlib/.batten-target-lock" ]
}

@test "a lock whose holder is dead is reclaimed, not waited out" {
	# flock's release came from the kernel; a directory's comes from the trap,
	# which a SIGKILLed holder never runs. Reclaim is what keeps that a delay of
	# one poll instead of the full timeout — a timeout here means it regressed.
	(exit 0) 3>&- &
	corpse=$!
	wait "$corpse" 2>/dev/null || true
	lock="$SYSROOT/lib/rustlib/.batten-target-lock"
	mkdir -p "$lock"
	echo "$corpse" >"$lock/pid"
	run env TARGET_LOCK_TIMEOUT=5 "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
}

@test "AN EMPTY PID FILE IS HELD, NEVER FREE — absence of evidence is not evidence" {
	# The subtlest rule this idiom asserts, and it had no row until CLOUD-428
	# generalised the idiom into `mise-tasks/singleton` and went looking for one.
	# An empty pid file is a holder caught between its `mkdir` and its write, not
	# a corpse; reading it as free is how two processes both believe they won,
	# which is the CLOUD-220 rollback this lock exists to prevent.
	#
	# Driven by the timeout, because the correct behaviour here is to WAIT: a
	# reclaim would be the bug. Deliberately short, since the assertion is that
	# it did not proceed, and every second past the first is spent proving it
	# again.
	lock="$SYSROOT/lib/rustlib/.batten-target-lock"
	mkdir -p "$lock"
	: >"$lock/pid"
	run env TARGET_LOCK_TIMEOUT=1 "$ENSURE" "$T"
	[ "$status" -eq 1 ]
	[[ "$output" == *"timed out waiting for the toolchain lock"* ]]
	# It waited rather than stealing: the lock is still the empty-pid holder's.
	[ -e "$lock" ]
	[ ! -s "$lock/pid" ]
	# And it never reached the effect the lock guards.
	[ ! -s "$STATE/calls" ]
}

@test "the pre-CLOUD-286 lock FILE does not wedge the directory lock" {
	# Every machine that ran doctor before CLOUD-286 has a regular file at this
	# path. mkdir can never succeed against it, so an unhandled one is a 600s
	# timeout on the first run after upgrading, on every existing checkout.
	mkdir -p "$SYSROOT/lib/rustlib"
	: >"$SYSROOT/lib/rustlib/.batten-target-lock"
	run env TARGET_LOCK_TIMEOUT=5 "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
}

@test "with no flock on PATH: acquires, serializes and releases" {
	# The case that would have caught CLOUD-286. flock(1) is util-linux and is
	# absent on macOS, so the proof is a PATH holding only what target-ensure
	# actually needs — not a stub named flock, which `command -v` would find.
	CLEAN="$BATS_TEST_TMPDIR/clean"
	mkdir -p "$CLEAN"
	for t in bash env cat dirname grep mkdir mv rm sleep; do
		ln -sf "$(command -v "$t")" "$CLEAN/$t"
	done
	ln -sf "$STUB/rustc" "$STUB/rustup" "$CLEAN/"
	run env -i PATH="$CLEAN" bash -c 'command -v flock'
	[ "$status" -ne 0 ]

	hold_lock 0.4
	run env -i PATH="$CLEAN" TARGET_LOCK_TIMEOUT=30 "$ENSURE" "$T"
	wait "$holder"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
	[ ! -e "$SYSROOT/lib/rustlib/.batten-target-lock" ]
}

@test "the task layer names no util-linux flock" {
	# The standing half of CLOUD-286: the dependency cannot come back by way of
	# a new call site. Comments are excluded on the same reasoning as the sweep
	# below — prose naming the binary is how the rule is explained.
	# `grep -r`, not a shell glob: `mise-tasks/` gained a nested task with
	# CLOUD-171 (`render/cli`), and `mise-tasks/*` stops at the directory — grep
	# warns and the file is never read. A sweep that silently skips a subtree is
	# the coverage claim mem:toolchain-and-hooks says to measure, not infer.
	run bash -c "grep -rhv '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise-tasks/' | grep -c 'flock'"
	[ "$output" = "0" ]
	run bash -c "grep -v '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise.toml' | grep -c 'flock'"
	[ "$output" = "0" ]
}

@test "target-ensure is the only live rustup-target-add in the task layer" {
	# The race cannot silently return via a new bare call site: every mutation
	# routes through this script's lock. Comments are excluded — prose citing
	# the command is how the rule is explained, not a violation of it — and so
	# are `<target>`-placeholder lines: a placeholder cannot execute, it is
	# usage text (dist's help), the same exemption shape attribution-check
	# gives coordinate lines.
	run bash -c "grep -rhv '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise-tasks/' | grep -v '<target>' | grep -c 'rustup target add'"
	[ "$output" = "1" ]
	run bash -c "grep -v '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise.toml' | grep -c 'rustup target add'"
	[ "$output" = "0" ]
}
