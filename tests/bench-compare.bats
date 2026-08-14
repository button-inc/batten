#!/usr/bin/env bats
# The regression gate's decision, exercised without building anything.
#
# Same separation as tests/bench-assert.bats, and the same reason: producing a
# paired measurement needs two release builds, a worktree and hyperfine, none of
# which belong in a pre-commit gate — but the thing that can silently rot is the
# COMPARISON, and it is a pure function of stdin. A regression gate that went
# dead would look exactly like a regression gate.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/bench-compare"
}

# A full pair, head within noise of base.
green_pair() {
	cat <<-'EOF'
		arm=base path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
		arm=head path=noop p50=2.44 p95=2.90 mean=2.47 runs=100
		arm=base path=check p50=2.50 p95=3.05 mean=2.55 runs=100
		arm=head path=check p50=2.47 p95=3.01 mean=2.52 runs=100
		arm=base path=hook p50=2.60 p95=3.03 mean=2.64 runs=100
		arm=head path=hook p50=2.62 p95=3.08 mean=2.66 runs=100
	EOF
}

@test "a pair within the threshold passes, and names the threshold" {
	run bash -c "'$GATE' <<'IN'
$(green_pair)
IN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"within 1.30x of the merge base"* ]]
}

@test "a path past the threshold is a regression, named with both arms and the ratio" {
	run bash -c "'$GATE' <<'IN'
arm=base path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
arm=head path=noop p50=2.44 p95=2.90 mean=2.47 runs=100
arm=base path=hook p50=2.60 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=9.10 p95=11.2 mean=9.30 runs=100
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"hook: base p50=2.60ms -> head p50=9.10ms (3.500x)"* ]]
	[[ "$output" != *"noop: base"* ]]
}

# The whole point of the ratio: an arm that is absolutely slow because the
# machine was busy drags BOTH arms, so the comparison still passes.
@test "a slow machine moves both arms and is not a regression" {
	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=26.0 p95=31.0 mean=26.4 runs=100
arm=head path=hook p50=26.4 p95=31.5 mean=26.8 runs=100
IN"
	[ "$status" -eq 0 ]
}

# A speed-up is not a regression, however large.
@test "a path that got faster passes" {
	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=9.10 p95=11.2 mean=9.30 runs=100
arm=head path=hook p50=2.60 p95=3.03 mean=2.64 runs=100
IN"
	[ "$status" -eq 0 ]
}

@test "the threshold is a boundary, not a suggestion" {
	# Exactly 1.30x is inside; a hair past it is not.
	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=2.00 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=2.60 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 0 ]

	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=2.00 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=2.62 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 1 ]
}

# The measured null maximum, asserted as a floor under the threshold. A gate set
# below the noise of a comparison that measures NOTHING is a coin flip, and the
# way that happens is somebody tightening the constant without re-running `mise
# run bench-pair --null`. This case fails the moment they do.
@test "the threshold clears the measured noise floor (n=30, max 1.102x)" {
	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=1.000 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=1.102 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 0 ]
}

@test "the threshold is honoured from the environment" {
	run bash -c "BENCH_REGRESSION_RATIO=1.05 '$GATE' <<'IN'
arm=base path=hook p50=2.00 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=2.30 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"threshold 1.05x"* ]]
}

# A head arm with no base arm means the base build measured less than it claims,
# and reporting green over a comparison that never happened is the
# partial-coverage false green.
@test "a head arm with no base arm is could-not-look, not a pass" {
	run bash -c "'$GATE' <<'IN'
arm=base path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
arm=head path=noop p50=2.44 p95=2.90 mean=2.47 runs=100
arm=head path=hook p50=2.62 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"measured on head but not on base"* ]]
}

@test "base arms alone are could-not-look — there is nothing to judge" {
	run bash -c "'$GATE' <<'IN'
arm=base path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no \`head\` measurements"* ]]
}

@test "empty stdin is could-not-look, and names the redirect" {
	run bash -c "'$GATE' </dev/null"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "an unpaired record shape is could-not-look and points at the line" {
	run bash -c "'$GATE' <<'IN'
arm=base path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
path=noop p50=2.44 p95=2.90 mean=2.47 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin:2:"* ]]
}

@test "an arm that is neither base nor head is malformed, not ignored" {
	run bash -c "'$GATE' <<'IN'
arm=middle path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin:1:"* ]]
}

@test "a zero base would divide, so it is malformed rather than infinite" {
	run bash -c "'$GATE' <<'IN'
arm=base path=hook p50=0 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=2.60 p95=3.08 mean=2.66 runs=100
IN"
	[ "$status" -eq 2 ]
}

@test "every regressed path is reported, not just the first" {
	run bash -c "'$GATE' <<'IN'
arm=base path=noop p50=2.00 p95=2.88 mean=2.44 runs=100
arm=head path=noop p50=8.00 p95=9.90 mean=8.47 runs=100
arm=base path=hook p50=2.60 p95=3.03 mean=2.64 runs=100
arm=head path=hook p50=9.10 p95=11.2 mean=9.30 runs=100
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"noop: base"* ]]
	[[ "$output" == *"hook: base"* ]]
}
