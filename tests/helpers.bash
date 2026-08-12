#!/usr/bin/env bash
# Shared bats helpers, for the utilities this tree calls that are NOT on a stock
# macOS (CLOUD-282).
#
# `verify` is the authorization the whole workflow contract rests on. On a Mac it
# could not pass, for reasons no branch caused, so an agent there either stopped
# on a red `verify` it did not break or landed on CI's word alone. CI is ubuntu,
# so CI is structurally blind to the whole class.
#
# Both helpers below stand in for a GNU tool at its CALL SITES rather than
# pinning the tool: `mise registry` carries neither, and pinning coreutils to
# supply one binary used only in tests is a large dependency for a small need.
#
# `load helpers` from a suite's setup; bats resolves it relative to the suite.

# Portable in-place sed. GNU sed treats `-i` with no attached suffix as "no
# backup"; BSD sed reads the NEXT ARGUMENT as the suffix, so `sed -i 's/a/b/' f`
# silently consumes the script as a filename extension there. `-i.bak` is the one
# spelling both accept, and the backup is removed so no call site has to know it
# was ever written.
sed_i() { # sed_i <script> <file>
	local script=$1 file=$2
	sed -i.bak "$script" "$file" || return 1
	rm -f "$file.bak"
}

# Portable stand-in for GNU coreutils `timeout(1)`, which macOS does not ship at
# all — so the nine call sites failed on a missing binary rather than on a flag.
#
# Usage: run_timeout [-s SIG] [-k SECS] SECS CMD...
#
# The EXIT CONTRACT is the load-bearing part, because the suites assert the
# numbers directly rather than merely "non-zero":
#
#   * the command finished in time      -> its own status, untouched
#   * it was killed and died of SIGKILL -> 137, i.e. 128 + 9. `main-watch.bats`
#     asserts this under `-s KILL`, which it uses because bash defers a trapped
#     signal until the running `sleep` returns.
#   * it was killed any other way       -> 124, GNU's timed-out status.
#     `land.bats` asserts this under `-k 1 5`.
#
# The watchdog is a background subshell rather than a trapped alarm: `trap` in
# the caller would fire in the bats process, and bats runs each `run` in its own
# subshell where an alarm handler is not reliably reached.
run_timeout() {
	local sig=TERM kill_after='' secs
	while :; do
		case "${1:-}" in
		-s)
			sig=$2
			shift 2
			;;
		-k)
			kill_after=$2
			shift 2
			;;
		*) break ;;
		esac
	done
	secs=$1
	shift

	"$@" &
	local pid=$!

	# The flag file, not a variable: the watchdog runs in a subshell, so nothing
	# it assigns is visible here. Its EXISTENCE is what distinguishes "we killed
	# it" from "it exited on its own with 143", which no exit status can.
	local fired="${BATS_TEST_TMPDIR:-/tmp}/run-timeout-fired.$$"
	rm -f "$fired"
	(
		sleep "$secs"
		kill -0 "$pid" 2>/dev/null || exit 0
		: >"$fired"
		kill -"$sig" "$pid" 2>/dev/null
		if [ -n "$kill_after" ]; then
			sleep "$kill_after"
			kill -KILL "$pid" 2>/dev/null
		fi
	) &
	local watchdog=$!

	local rc=0
	wait "$pid" || rc=$?

	# Reap the watchdog before returning, or its `sleep` outlives the test and
	# bats blocks on the inherited pipe waiting for a writer that will not close.
	kill "$watchdog" 2>/dev/null
	wait "$watchdog" 2>/dev/null

	if [ -e "$fired" ]; then
		rm -f "$fired"
		[ "$rc" -eq 137 ] && return 137
		return 124
	fi
	return "$rc"
}
