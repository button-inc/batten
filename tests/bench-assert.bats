#!/usr/bin/env bats
# The decision half of CLOUD-207's latency mechanism, exercised without ever
# measuring anything.
#
# That separation is the point of the suite, not an economy: `mise run bench`
# needs a release build, hyperfine and a quiet machine, none of which belong on
# the landing path — but the thing that can silently rot is the DECISION, and it
# is a pure function of stdin. So this runs in the hk gate on every commit, over
# heredocs, in milliseconds. A published latency number whose gate went dead
# would look exactly like a published latency number.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/bench-assert"
	README="$BATS_TEST_TMPDIR/README.md"
	# The published table this gate holds its own budgets against. Written per
	# test so a case can make it disagree; the real file is asserted separately.
	cat >"$README" <<-'EOF'
		## Performance

		| path    | p50    | p95    | budget    |
		| ------- | ------ | ------ | --------- |
		| `noop`  | 2.6 ms | 3.3 ms | ≤ 100 ms  |
		| `check` | 2.5 ms | 3.2 ms | —         |
		| `hook`  | 2.7 ms | 3.5 ms | ≤ 100 ms  |
	EOF
}

# A full set of records, all comfortably inside budget.
green_records() {
	cat <<-'EOF'
		path=noop p50=2.59 p95=3.27 mean=2.67 runs=100
		path=check p50=2.54 p95=3.17 mean=2.64 runs=100
		path=hook p50=2.72 p95=3.48 mean=2.96 runs=100
	EOF
}

@test "records inside budget pass, and say so" {
	run bash -c "'$GATE' '$README' <<'IN'
$(green_records)
IN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"inside its budget"* ]]
}

@test "the real README publishes the budgets this gate enforces" {
	run bash -c "'$GATE' '$BATS_TEST_DIRNAME/../README.md' <<'IN'
$(green_records)
IN"
	[ "$status" -eq 0 ]
}

@test "a budgeted path over its budget is a violation, and is named" {
	run bash -c "'$GATE' '$README' <<'IN'
path=noop p50=2.59 p95=3.27 mean=2.67 runs=100
path=check p50=2.54 p95=3.17 mean=2.64 runs=100
path=hook p50=90.1 p95=140.5 mean=95.2 runs=100
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"hook: p95=140.5ms exceeds the 100ms budget"* ]]
	# The path that is inside budget is not reported alongside it.
	[[ "$output" != *"noop: p95"* ]]
}

# `check` is measured and deliberately not gated: its cost is bounded by the
# repository it is pointed at, not by batten, so no ceiling here could tell a
# large tree apart from a regression.
@test "the ungated path is never a violation, however slow" {
	run bash -c "'$GATE' '$README' <<'IN'
path=noop p50=2.59 p95=3.27 mean=2.67 runs=100
path=check p50=800.0 p95=1200.0 mean=850.0 runs=100
path=hook p50=2.72 p95=3.48 mean=2.96 runs=100
IN"
	[ "$status" -eq 0 ]
}

# Absence is `could not look`, never a pass: a run that measured two of three
# paths and reported green over the two is the partial-coverage false green.
@test "a budgeted path missing from the records is exit 2, not a pass" {
	run bash -c "'$GATE' '$README' <<'IN'
path=noop p50=2.59 p95=3.27 mean=2.67 runs=100
path=check p50=2.54 p95=3.17 mean=2.64 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"hook: budgeted here, absent from stdin"* ]]
}

@test "empty stdin is exit 2, and names the redirect" {
	run bash -c "'$GATE' '$README' </dev/null"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "whitespace-only stdin is empty, not malformed" {
	run bash -c "printf '  \n\n' | '$GATE' '$README'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "a line that is not a record is exit 2 and points at the line" {
	run bash -c "'$GATE' '$README' <<'IN'
path=noop p50=2.59 p95=3.27 mean=2.67 runs=100
Benchmark 1: target/release/batten --help
path=hook p50=2.72 p95=3.48 mean=2.96 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin:2:"* ]]
}

@test "a record whose p95 is not a number is malformed, not zero" {
	run bash -c "'$GATE' '$README' <<'IN'
path=noop p50=2.59 p95=NaN mean=2.67 runs=100
path=hook p50=2.72 p95=3.48 mean=2.96 runs=100
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin:1:"* ]]
}

# Non-negotiable rule 2: the rule ships with its mechanism, so the published
# budget and the enforced one cannot be two authorities for one number.
@test "a README publishing a different budget fails" {
	sed -i 's/| `hook`  | 2.7 ms | 3.5 ms | ≤ 100 ms  |/| `hook`  | 2.7 ms | 3.5 ms | ≤ 250 ms  |/' "$README"
	run bash -c "'$GATE' '$README' <<'IN'
$(green_records)
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"enforced 100ms"* ]]
	[[ "$output" == *"250"* ]]
}

@test "a README with no row for a budgeted path fails" {
	sed -i '/`hook`/d' "$README"
	run bash -c "'$GATE' '$README' <<'IN'
$(green_records)
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no row for it"* ]]
}

@test "a missing README is could-not-look, not a pass" {
	run bash -c "'$GATE' '$BATS_TEST_TMPDIR/absent.md' <<'IN'
$(green_records)
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not found"* ]]
}
