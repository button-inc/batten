#!/usr/bin/env bats
# subject: mise-tasks/nonverdict-assert
# CLOUD-484. The decider half of the non-verdict-failure sensor: how many recent CI
# jobs failed without reaching a verdict, judged against a budget.
#
# A pure function of stdin, so this suite needs no network and no `gh` — which is
# what lets it run in the hk gate on every commit while the measurement runs on a
# clock. Readings are injected the way `bench-assert` and `branch-age-check` inject
# theirs.

setup() {
	ASSERT="$BATS_TEST_DIRNAME/../mise-tasks/nonverdict-assert"
	export BATTEN_NONVERDICT_MAX=2
}

# One `window` summary with the counts a case cares about. Tab-separated, the record
# format `nonverdict-scan` emits.
window() {
	printf 'window\truns=%s\tfailed_jobs=%s\tnonverdict=%s\tverdict=%s\tunreadable=%s\n' \
		"${1:-10}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-0}"
}

# The step name a toolchain-install failure really carries. Declared once, with
# the FULL pin: `attribution-check` exempts a pinned coordinate and refuses a bare
# vendor mention in prose, and the full sha is what the API actually returns.
TOOLCHAIN_STEP='Run jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654'

nonverdict_line() {
	printf 'nonverdict\trun=%s\tjob=%s\tstep=%s\n' "$1" "$2" "$3"
}

verdict_line() {
	printf 'verdict\trun=%s\tjob=%s\tstep=%s\n' "$1" "$2" "$3"
}

@test "under budget is a pass, and says what it judged" {
	run bash -c "{ $(declare -f window); window 10 2 2 0 0; } | '$ASSERT'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 of 10"* ]]
}

@test "THE ACCEPTANCE CASE: over budget fails and names each non-verdict failure" {
	input=$(
		window 10 3 3 0 0
		nonverdict_line 111 "ci" "$TOOLCHAIN_STEP"
		nonverdict_line 222 "msrv" "$TOOLCHAIN_STEP"
		nonverdict_line 333 "cross" "Run actions/checkout@3d3c42e"
	)
	run bash -c "printf '%s\n' \"\$1\" | '$ASSERT'" _ "$input"
	[ "$status" -eq 1 ]
	[[ "$output" == *"over the budget of 2"* ]]
	[[ "$output" == *"run=111"* ]]
	[[ "$output" == *"run=333"* ]]
}

@test "a VERDICT failure is not counted, however many there are" {
	# The other direction, so the predicate cannot collapse into counting every red
	# job. Ten genuine test failures are not this gate's business.
	input=$(
		window 10 10 0 10 0
		verdict_line 111 "ci" "Run mise run test:bats"
		verdict_line 222 "ci" "Run mise run lint:clippy"
	)
	run bash -c "printf '%s\n' \"\$1\" | '$ASSERT'" _ "$input"
	[ "$status" -eq 0 ]
}

@test "COULD NOT LOOK: an unreadable run in the window is exit 2, never a pass" {
	# `bench-assert`'s partial-coverage rule. A window that read less than it
	# claims must not report green over the part it managed.
	run bash -c "{ $(declare -f window); window 10 1 1 0 1; } | '$ASSERT'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not read"* ]]
}

@test "an unreadable run is exit 2 even when the count is under budget" {
	# The trap: 1 non-verdict is under a budget of 2, so a naive order of checks
	# would report green and hide that the window was incomplete.
	run bash -c "{ $(declare -f window); window 10 1 1 0 3; } | '$ASSERT'"
	[ "$status" -eq 2 ]
}

@test "empty stdin is exit 2, not a clean window" {
	run bash -c ": | '$ASSERT'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "records with no window summary are exit 2 — there is no window to judge" {
	input=$(nonverdict_line 111 "ci" "$TOOLCHAIN_STEP")
	run bash -c "printf '%s\n' \"\$1\" | '$ASSERT'" _ "$input"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no \`window\` summary"* ]]
}

@test "two concatenated scans are exit 2 — a count over both describes neither" {
	run bash -c "{ $(declare -f window); window 10 1 1 0 0; window 5 0 0 0 0; } | '$ASSERT'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"more than one"* ]]
}

@test "a non-numeric count is exit 2 rather than being coerced to zero" {
	run bash -c "printf 'window\truns=10\tfailed_jobs=1\tnonverdict=lots\tverdict=0\tunreadable=0\n' | '$ASSERT'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"nonverdict"* ]]
}

@test "ANTI-VACUITY: an empty window exits 0 and says it judged nothing" {
	# A gate that cannot fire must not be indistinguishable from one that found
	# nothing — the `finding-sink-check` lesson.
	run bash -c "{ $(declare -f window); window 0 0 0 0 0; } | '$ASSERT'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to judge"* ]]
}

@test "the budget is raise-only overridable, which is how the window is retuned" {
	# The same records that fail at the default budget of 2 pass at 5 — which is
	# also what lets a case point the budget at a fixture rather than editing the
	# task.
	export BATTEN_NONVERDICT_MAX=5
	input=$(window 10 3 3 0 0)
	run bash -c "printf '%s\n' \"\$1\" | '$ASSERT'" _ "$input"
	[ "$status" -eq 0 ]
}

@test "POINTER, NEVER PAYLOAD: the report carries no step output, only coordinates" {
	# The records themselves never contain a log body, so the assertion here is
	# that the gate does not invent one — it echoes the coordinate line and nothing
	# else.
	input=$(
		window 10 3 3 0 0
		nonverdict_line 111 "ci" "$TOOLCHAIN_STEP"
		nonverdict_line 222 "ci" "$TOOLCHAIN_STEP"
		nonverdict_line 333 "ci" "$TOOLCHAIN_STEP"
	)
	run bash -c "printf '%s\n' \"\$1\" | '$ASSERT'" _ "$input"
	[ "$status" -eq 1 ]
	[[ "$output" != *"curl"* ]]
	[[ "$output" != *"503"* ]]
}
