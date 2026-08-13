#!/usr/bin/env bats
# CLOUD-509. The decision table for `hook-latency-drift`, the clock half of the
# two-tier gate.
#
# `hk` is stubbed throughout. The task's subject is a wall clock, so a suite that
# ran the real gate would take minutes per case and measure this container's mood
# rather than the task's arithmetic. A stub that sleeps a known amount makes the
# three verdicts reachable in seconds, and the thresholds are what this pins —
# the measurement itself is the runner's job, not the suite's.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/hook-latency-drift"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH
	# Three runs is the task's default and the suite's cost floor; every case
	# pays it, so keep the stub's sleep small.
	export BATTEN_HOOK_BUDGET_RUNS=3
}

# An `hk` that takes a known number of seconds and says nothing.
stub_hk() {
	printf '#!/usr/bin/env bash\nsleep %s\nexit 0\n' "$1" >"$STUB/hk"
	chmod +x "$STUB/hk"
}

@test "a tier inside its budget passes" {
	stub_hk 2
	BATTEN_HOOK_BUDGET_SECONDS=2 BATTEN_HOOK_BUDGET_SLACK=1 \
		BATTEN_HOOK_BUDGET_LOOSE_FACTOR=100 run "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"within the 2s budget"* ]]
}

@test "a tier over budget plus slack is drift-tight" {
	# The direction that matters day to day: a step grew, or one joined the fast
	# tier that belongs in the slow one.
	stub_hk 2
	BATTEN_HOOK_BUDGET_SECONDS=0 BATTEN_HOOK_BUDGET_SLACK=0 run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"drift-tight"* ]]
}

@test "slack absorbs a small overshoot rather than crying wolf" {
	# A shared runner's wall clock moves run to run. A report that fires on that
	# is a report nobody reads, which is worse than no report.
	stub_hk 2
	BATTEN_HOOK_BUDGET_SECONDS=1 BATTEN_HOOK_BUDGET_SLACK=5 \
		BATTEN_HOOK_BUDGET_LOOSE_FACTOR=100 run "$TASK"
	[ "$status" -eq 0 ]
}

@test "a tier far under budget is drift-loose, not a silent pass" {
	# The ratchet. Without this the budget rots upward: the tier gets faster,
	# nobody re-derives the number, and the ceiling stops bounding anything.
	stub_hk 0
	BATTEN_HOOK_BUDGET_SECONDS=30 BATTEN_HOOK_BUDGET_SLACK=5 \
		BATTEN_HOOK_BUDGET_LOOSE_FACTOR=3 run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"drift-loose"* ]]
}

@test "a red gate is still timed, because cost is not correctness" {
	# The task reports what the tier COSTS. A failing step still takes time, and
	# treating a red gate as unmeasurable would blind the report exactly when a
	# branch is broken.
	printf '#!/usr/bin/env bash\nsleep 2\nexit 1\n' >"$STUB/hk"
	chmod +x "$STUB/hk"
	BATTEN_HOOK_BUDGET_SECONDS=2 BATTEN_HOOK_BUDGET_SLACK=1 \
		BATTEN_HOOK_BUDGET_LOOSE_FACTOR=100 run "$TASK"
	[ "$status" -eq 0 ]
}

@test "no hk on PATH is could-not-look, never a verdict" {
	rm -f "$STUB/hk"
	PATH="$STUB:/usr/bin:/bin" run "$TASK"
	[ "$status" -eq 2 ]
}
