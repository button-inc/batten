#!/usr/bin/env bats
# tests/helpers.bash stands in for two GNU tools a stock macOS does not ship
# (CLOUD-282), at call sites that assert exact numbers. `run_timeout`'s exit
# mapping is the subtle half — nine call sites across three suites now depend on
# it, and a helper that returned merely "non-zero" would make every one of them
# pass vacuously. So each branch of the mapping is pinned here.

setup() {
	load helpers
}

@test "a command that finishes in time keeps its OWN exit status" {
	# The pass-through case, and the one a naive implementation gets wrong by
	# reporting the watchdog's status instead.
	run run_timeout 10 bash -c 'exit 7'
	[ "$status" -eq 7 ]

	run run_timeout 10 true
	[ "$status" -eq 0 ]
}

@test "a timed-out command is 124, GNU's timed-out status" {
	# tests/land.bats asserts this number directly: 124 is the result that case
	# is proving, not a failure of it.
	run run_timeout 1 sleep 30
	[ "$status" -eq 124 ]
}

@test "-s KILL reports 137, because the child died of SIGKILL" {
	# tests/main-watch.bats asserts 137. It uses KILL rather than the default
	# TERM because bash defers a trapped signal until the running `sleep`
	# returns, so a TERM would cost every blocking case a full poll interval.
	run run_timeout -s KILL 1 sleep 30
	[ "$status" -eq 137 ]
}

@test "-k on a subject that dies to TERM is 124 — the escalation never fires" {
	# tests/land.bats' shape: `land` takes the TERM, so `-k` is insurance and the
	# answer is the plain timed-out status. Measured against GNU coreutils
	# 2026-08-11 and matched here, rather than assumed.
	run run_timeout -k 1 1 sleep 30
	[ "$status" -eq 124 ]
}

@test "-k that actually escalates is 137, matching GNU" {
	# The half worth measuring rather than guessing: GNU reports the SIGNAL that
	# ended the child, not the timeout, once the escalation is what ended it —
	# verified against real coreutils, which answers 137 for exactly this
	# subject. A helper that answered 124 here would disagree with the tool it
	# replaces in the one case the two could differ.
	run run_timeout -k 1 1 bash -c 'trap "" TERM; sleep 30'
	[ "$status" -eq 137 ]
}

@test "a command killed by a signal it raised ITSELF is not a timeout" {
	# The distinction the flag file exists for: 143 is TERM, the same status a
	# TERM-timeout produces, so an implementation reading only the exit status
	# would report this as 124 and hide a genuine crash.
	run run_timeout 10 bash -c 'kill -TERM $$'
	[ "$status" -eq 143 ]
}

@test "sed_i edits in place and leaves no backup behind" {
	# `-i.bak` is the one spelling GNU and BSD both accept; the backup is an
	# artifact of portability, so the helper removes it and no call site has to
	# know it existed. A stray .bak would break suites that list a fixture dir.
	local f="$BATS_TEST_TMPDIR/subject"
	printf 'alpha\nbeta\n' >"$f"
	sed_i 's/alpha/gamma/' "$f"
	[ "$(cat "$f")" = "$(printf 'gamma\nbeta')" ]
	[ ! -e "$f.bak" ]
	run ls "$BATS_TEST_TMPDIR"
	[[ "$output" != *".bak"* ]]
}

@test "sed_i propagates a failing sed rather than reporting success" {
	# A gate helper that swallowed the status would be the CLOUD-199 shape in
	# miniature: the edit silently not happening, reported green.
	run sed_i 's/unterminated' "$BATS_TEST_TMPDIR/absent"
	[ "$status" -ne 0 ]
}
