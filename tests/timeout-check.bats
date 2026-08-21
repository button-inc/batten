#!/usr/bin/env bats
# subject: mise-tasks/timeout-check
# The commit half of CLOUD-266: every workflow job's `timeout-minutes` carries a
# budget comment that justifies it.
#
# The gate deliberately does NOT check the limit. Every job already declared one,
# and at 3.4x–75x of measured p95 those numbers bound nothing and ratchet
# nothing. What is checkable about a commit is whether the number was justified,
# so that is what this suite pins — including that `grandfathered` passes, since
# a gate everything fails on day one is a gate that gets reverted on day one.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/timeout-check"
	WF="$BATS_TEST_TMPDIR/wf.yml"
}

# A one-job workflow whose job body is exactly the lines given.
workflow_with() {
	local target=${2:-$WF}
	{
		printf 'name: t\n'
		printf 'on:\n  push:\n'
		printf 'jobs:\n'
		printf '  build:\n'
		printf '    runs-on: ubuntu-latest\n'
		[ -z "$1" ] || printf '%s\n' "$1"
		printf '    steps:\n      - run: true\n'
	} >"$target"
}

@test "the repo's real workflows all carry a justified budget today" {
	# The grandfathering claim, made checkable rather than asserted. It fails the
	# day someone adds a job without a budget — which is the whole mechanism.
	run "$GATE" "$BATS_TEST_DIRNAME"/../.github/workflows/*.yml
	[ "$status" -eq 0 ]
	[[ "$output" == *"every timeout justified"* ]]
}

@test "a grandfathered budget passes — dated debt is the day-one state" {
	workflow_with '    timeout-minutes: 15 # budget: grandfathered measured=2026-08-10'
	run "$GATE" "$WF"
	[ "$status" -eq 0 ]
}

@test "a measured budget whose arithmetic agrees passes" {
	# ceil(267 * 3 / 60) == 14
	workflow_with '    timeout-minutes: 14 # budget: p95=267s x3 measured=2026-08-10'
	run "$GATE" "$WF"
	[ "$status" -eq 0 ]
}

@test "a job with no timeout-minutes is caught, and the pointer names the job" {
	workflow_with ''
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"build"* ]]
	[[ "$output" == *"no-timeout"* ]]
}

@test "a timeout with no budget comment is caught" {
	workflow_with '    timeout-minutes: 15'
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"build"* ]]
	[[ "$output" == *"no-budget"* ]]
}

@test "a malformed budget comment is caught" {
	workflow_with '    timeout-minutes: 15 # budget: because I said so'
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"malformed-budget"* ]]
}

@test "a budget comment missing its measured= date is malformed, not accepted" {
	workflow_with '    timeout-minutes: 15 # budget: grandfathered'
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"malformed-budget"* ]]
}

@test "a measured budget whose declared minutes disagree with its own arithmetic is caught" {
	workflow_with '    timeout-minutes: 99 # budget: p95=267s x3 measured=2026-08-10'
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"budget-arithmetic"* ]]
	# The refusal names both numbers, so it is actionable without re-deriving it.
	[[ "$output" == *"14m"* ]]
}

@test "a per-job multiplier is refused — the multiplier is one repo-wide constant" {
	# Loosening it anywhere must read as loosening it everywhere, so a row cannot
	# quietly pick its own headroom.
	workflow_with '    timeout-minutes: 41 # budget: p95=267s x9 measured=2026-08-10'
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"budget-multiplier"* ]]
}

@test "a step-level timeout does not satisfy the job's obligation" {
	# `timeout-minutes` is anchored at job indentation. A step's timeout is the
	# step's business; letting it count would let a job go unbounded while the
	# gate reported green.
	{
		printf 'name: t\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
		printf '    steps:\n      - run: true\n        timeout-minutes: 5 # budget: grandfathered measured=2026-08-10\n'
	} >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-timeout"* ]]
}

@test "a matrix job passes with one budget covering every leg" {
	# release-artifacts.yml's `dist` shape: a single timeout-minutes over seven
	# targets. Beside-the-value needs no key scheme to say so.
	{
		printf 'name: t\non:\n  push:\njobs:\n  dist:\n    runs-on: ubuntu-latest\n'
		printf '    timeout-minutes: 30 # budget: grandfathered measured=2026-08-10\n'
		printf '    strategy:\n      matrix:\n        target: [a, b, c]\n'
		printf '    steps:\n      - run: true\n'
	} >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 0 ]
}

@test "prose that merely mentions a budget does not satisfy any job" {
	# These workflows are heavily commented, and a gate that fires on — or is
	# satisfied by — its own documentation is a gate people delete.
	{
		printf 'name: t\n'
		printf '# budget: grandfathered measured=2026-08-10 (explaining the grammar)\n'
		printf 'on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
		printf '    timeout-minutes: 15\n    steps:\n      - run: true\n'
	} >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-budget"* ]]
}

@test "every offender is reported in one pass, not just the first" {
	# fail_fast = false in hk.pkl: one fix revealing the next on the following run
	# is how a batch of small corrections becomes N round trips.
	{
		printf 'name: t\non:\n  push:\njobs:\n'
		printf '  one:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - run: true\n'
		printf '  two:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15 # budget: junk\n    steps:\n      - run: true\n'
		printf '  three:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n'
	} >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"3 job(s) without a justified budget"* ]]
	[[ "$output" == *"one"* ]]
	[[ "$output" == *"two"* ]]
	[[ "$output" == *"three"* ]]
}

@test "a file with no jobs: block is exit 2, never a pass" {
	# For this gate a silent pass means reporting green over a file it failed to
	# read — the failure mode that gets a gate switched off.
	printf 'name: t\non:\n  push:\n' >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 2 ]
}

@test "a jobs: block with no job keys under it is exit 2, never a pass" {
	printf 'name: t\non:\n  push:\njobs:\n' >"$WF"
	run "$GATE" "$WF"
	[ "$status" -eq 2 ]
}

@test "a missing file is exit 2, never a pass" {
	run "$GATE" "$BATS_TEST_TMPDIR/absent.yml"
	[ "$status" -eq 2 ]
}

@test "the gate makes no network call" {
	# A stub that fails loudly if the gate reaches for the API — the technique
	# tests/release-assets-check.bats already uses. This half is a property of the
	# commit; anything remote belongs to timeout-drift.
	mkdir -p "$BATS_TEST_TMPDIR/bin"
	printf '#!/bin/sh\necho "gh was invoked" >&2\nexit 99\n' >"$BATS_TEST_TMPDIR/bin/gh"
	chmod +x "$BATS_TEST_TMPDIR/bin/gh"
	workflow_with '    timeout-minutes: 15 # budget: grandfathered measured=2026-08-10'
	PATH="$BATS_TEST_TMPDIR/bin:$PATH" run "$GATE" "$WF"
	[ "$status" -eq 0 ]
	[[ "$output" != *"gh was invoked"* ]]
}
