#!/usr/bin/env bats
# The shell suite was 83% of the CI critical path (CLOUD-386): 247.01s of the
# `ci` job's 298.87s, 778 tests run one at a time, and `verify` pays it a second
# time on every `land` lap. Parallelising it is the change; this is its gate.
#
# A speed-up is the one kind of fix that rots silently. Nothing fails when the
# `--jobs` flag is dropped in a merge or edited away — the suite still passes,
# just slower, and the cost reappears in the lap economics where no gate is
# looking. `timeout-check`'s ceiling cannot catch it either: 3.4x headroom over
# p95 (CLOUD-352) absorbs a return to serial without a single red build.
#
# So the rule ships with its mechanism (AGENTS.md non-negotiable 2): the
# invocation is a computable predicate over mise.toml, and a revert to serial is
# an exit code rather than a slower Tuesday.
#
# Output is a pointer, never a payload (non-negotiable 4): these assertions name
# the flag and the tool, never suite output.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	# The task body as mise sees it: the `run = "..."` line of [tasks."test:bats"].
	# Read from the manifest rather than from `mise tasks --json` so the gate
	# holds without provisioning anything, the same reason task-fail-closed.bats
	# reads the verify body directly.
	RUN=$(awk '/^\[tasks\."test:bats"\]/{f=1} f&&/^run = /{print; exit}' mise.toml)
	INSTALL_ARGS=$(awk '/^  ci:/{f=1} f&&/install_args:/{print; exit}' .github/workflows/ci.yml)
}

@test "the test:bats invocation was found at all — this suite is not passing vacuously" {
	[ -n "$RUN" ]
	[[ "$RUN" == *"bats"* ]]
	[[ "$RUN" == *"tests/*.bats"* ]]
}

@test "the suite runs in parallel — a silent revert to serial is this gate's whole purpose" {
	[[ "$RUN" == *"--jobs"* ]]
}

@test "the job count is derived from the machine, never a hand-typed number that outlives its runner" {
	# `$(nproc)` rather than a literal: the 4 that is right for today's
	# ubuntu-latest is wrong the moment a runner changes size, and a stale
	# literal reads as deliberate.
	[[ "$RUN" == *'--jobs "$(nproc)"'* ]]
}

@test "a jobs count of 1 is refused — that is serial wearing the flag's costume" {
	[[ "$RUN" != *"--jobs 1"* ]]
	[[ "$RUN" != *"-j 1"* ]]
}

@test "tests are parallelised across files only, never within one" {
	# Within-file parallelism would run a file's setup/teardown concurrently
	# with its own cases. The suites here are overwhelmingly pure predicates
	# over strings, but the ones that touch real toolchain state
	# (target-ensure.bats, anything invoking doctor) are exactly the ones a
	# within-file schedule would interleave. Across-files is already enough:
	# the largest file is 49 of 778 tests, so the schedule is not tail-bound.
	[[ "$RUN" == *"--no-parallelize-within-files"* ]]
}

@test "the parallel backend is named explicitly rather than left to bats' default probe" {
	# bats defaults to looking for GNU parallel, which is not in the mise
	# registry and so is pinned nowhere here. Naming rush is what makes the
	# parallel path a provisioned dependency instead of whatever the host
	# happens to carry.
	[[ "$RUN" == *"--parallel-binary-name rush"* ]]
}

@test "the parallel backend is a pinned tool, so the fast path cannot depend on the host" {
	run grep -qE '^"aqua:shenwei356/rush" = ' mise.toml
	[ "$status" -eq 0 ]
}

@test "CI installs the parallel backend — an absent rush is a missing TOOL, not a slow suite" {
	# ci-tools-check asserts every name in install_args resolves to a [tools]
	# entry. It cannot assert the converse: that a tool the gate NEEDS is in
	# the list. Without this, the `ci` job would provision no rush and the
	# fastest step in the gate would be the one that cannot start.
	[ -n "$INSTALL_ARGS" ]
	[[ "$INSTALL_ARGS" == *"aqua:shenwei356/rush"* ]]
}
