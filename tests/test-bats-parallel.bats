#!/usr/bin/env bats
# subject: mise.toml
# The shell suite was 83% of the CI critical path (CLOUD-386): 247.01s of the
# `ci` job's 298.87s, run one at a time, and `verify` pays it a second time on
# every `land` lap. Parallelising it is the change; this is its gate.
#
# It is still the pole after parallelising — 100s of a 111s hk gate, measured
# in-gate on a 4-core box (CLOUD-439) — which is why the job count is swept and
# pinned rather than merely present, and why the count of cases that actually
# RAN is asserted. A suite that gets faster by losing tests is the failure mode
# every change in this series risks.
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
	# The task body as mise sees it: the whole [tasks."test:bats"] block, bounded
	# by the next table header. Read from the manifest rather than from `mise
	# tasks --json` so the gate holds without provisioning anything, the same
	# reason task-fail-closed.bats reads the verify body directly. The block
	# form (was: the single `run = ` line) follows the body growing its
	# step-receipt wrapper (CLOUD-424); every assertion below is a substring
	# match, so the wider net changes nothing they hold.
	RUN=$(awk '/^\[tasks\."test:bats"\]/{f=1;next} f&&/^\[tasks/{exit} f' mise.toml)
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
	#
	# Derived ONCE and read from a variable (CLOUD-439). The body reports the
	# count it used, and a second `$(nproc)` to print it would be a second
	# authority for one number — the shape non-negotiable 6 refuses, and the
	# exact defect CLOUD-439 went looking for elsewhere.
	[[ "$RUN" == *'workers=$(nproc)'* ]]
	[[ "$RUN" == *'--jobs "$workers"'* ]]
	run grep -cE '^[^#]*nproc' mise.toml
	[ "$status" -eq 0 ]
	[ "$output" -eq 1 ]
}

@test "the job count is not capped below the machine — that was measured, and it is a large regression" {
	# CLOUD-439 swept this in both directions in-gate on a 4-core box: at 2
	# workers `test:bats` went 100.3s -> 210.7s and the whole gate 111.1s ->
	# 224.9s. This suite is the pole of the gate, so workers taken off it cost
	# far more than the oversubscription they relieve. The sweep is recorded
	# beside the invocation; this is the half that makes re-capping it red
	# rather than merely slow, since `timeout-check` has 3.4x headroom over p95
	# and would absorb the regression invisibly. A count of 1 has its own case
	# below; this one refuses every fraction of the machine between them.
	[[ "$RUN" != *'nproc) / '* ]]
	[[ "$RUN" != *'nproc)/'* ]]
}

@test "the run asserts how many cases it executed, not merely that none failed" {
	# The failure mode every change in this series risks is "faster because it
	# ran fewer", and a green exit code is blind to it. The body counts the
	# tracked @test declarations and compares them against bats' own report;
	# neither number is written down, so adding a case needs no edit here.
	#
	# JUNIT rather than TAP since CLOUD-352, and the property is unchanged: both
	# formatters report one element per executed case, and the two populations
	# were verified equal at 2558 on one tree before the swap. What junit adds is
	# the SUITE a case belongs to, which TAP does not carry and which is what
	# `mise run suite-bench` needs to attribute cost per file.
	[[ "$RUN" == *"--report-formatter junit"* ]]
	[[ "$RUN" == *"git grep -c '^@test '"* ]]
	[[ "$RUN" == *'"$ran" != "$expected"'* ]]
	# Pointer, never payload (rule 4): the failure names counts, never a case.
	[[ "$RUN" == *'of $expected cases reported by the runner'* ]]
}

@test "the report survives the run, or the cost corpus has no source" {
	# CLOUD-352. The report used to go to `mktemp -d` under a `trap rm`, so the
	# only per-case timings this repository produces were discarded microseconds
	# after being written. `suite-bench` derives the per-suite corpus from what is
	# left behind, which is what keeps it free — re-running 2,600 cases to measure
	# them would cost more than the waste it reports.
	#
	# So the deletion must not come back, and this is the row that notices. It is
	# not a style assertion: a re-added `trap` would leave `suite-bench` reporting
	# could-not-look forever, which is quiet.
	# Anchored on the ASSIGNMENT, not the word: the body's own comment explains
	# the mechanism it replaced, so a bare `mktemp -d` match fires on the
	# explanation and the row judges prose instead of code. Caught by this case
	# failing against a body that was already correct.
	[[ "$RUN" != *'report=$(mktemp'* ]]
	[[ "$RUN" != *"trap 'rm -rf"* ]]
	# Under `target/`, which is gitignored, so a run cannot dirty the tree.
	[[ "$RUN" == *"target/bats-report"* ]]
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
	# the largest file is 54 of 1039 cases — ~21% of a worker's share at the
	# measured-optimal four workers — so the schedule is not tail-bound.
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
