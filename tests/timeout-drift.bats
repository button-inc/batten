#!/usr/bin/env bats
# subject: mise-tasks/timeout-drift.sh
# The world half of CLOUD-266: is each committed budget still true?
#
# Driven entirely through a stubbed `gh`, so every verdict is reachable without a
# token and without the network. The scheduled half is otherwise not gated by this
# suite, and that is deliberate: its correctness is that it REPORTS rather than
# blocks, which is a property of where it runs, not of what it computes.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/timeout-drift.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	WORKFLOWS="$BATS_TEST_TMPDIR/workflows"
	mkdir -p "$STUB" "$WORKFLOWS"
	PATH="$STUB:$PATH"
	export PATH
	# Small window and minimum so a fixture needs a handful of runs, not 25.
	export BATTEN_BUDGET_MIN_SAMPLES=5
	export BATTEN_BUDGET_WINDOW=10
}

# A one-job workflow carrying the given `timeout-minutes` line.
workflow_with() {
	{
		printf 'name: t\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
		printf '%s\n' "$1"
		printf '    steps:\n      - run: true\n'
	} >"$WORKFLOWS/t.yml"
}

# `gh` answering with `count` successful runs of `job`, each lasting `secs`.
# Run ids are 1..count; every run reports one job.
stub_gh() {
	local job=$1 count=$2 secs=$3
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
[ ! -f "$BATS_TEST_TMPDIR/gh.fails" ] || exit 1
case "\$*" in
  *"/runs?status=success"*) seq 1 $count ;;
  *"/jobs"*) printf '%s\t1970-01-01T00:00:00Z\t1970-01-01T00:%02d:%02dZ\n' "$job" $(($secs / 60)) $(($secs % 60)) ;;
esac
EOF
	chmod +x "$STUB/gh"
}

# As above, but the job reports as a matrix leg: `<job> (<leg>)`.
stub_gh_matrix() {
	local job=$1 count=$2 secs=$3
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *"/runs?status=success"*) seq 1 $count ;;
  *"/jobs"*)
    for leg in one two three; do
      printf '%s (%s)\t1970-01-01T00:00:00Z\t1970-01-01T00:%02d:%02dZ\n' "$job" "\$leg" $(($secs / 60)) $(($secs % 60))
    done
    ;;
esac
EOF
	chmod +x "$STUB/gh"
}

@test "a measured budget matching its measurement reports clean" {
	# p95 = 100s, x3 = 300s, ceil to 5m — exactly what is declared.
	stub_gh build 6 100
	workflow_with '    timeout-minutes: 5 # budget: p95=100s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 0 ]
	[[ "$output" == *"still matches its measurement"* ]]
}

@test "a budget the measurement has outgrown reports drift-tight, naming both numbers" {
	# p95 = 600s, x3 = 1800s = 30m, but only 5m is declared.
	stub_gh build 6 600
	workflow_with '    timeout-minutes: 5 # budget: p95=100s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"drift-tight"* ]]
	[[ "$output" == *"600s"* ]]
	[[ "$output" == *"30m"* ]]
}

@test "a budget gone slack because the job got faster reports drift-loose — the ratchet" {
	# The direction a tightness-only report would let rot upward forever.
	# p95 = 60s, x3 = 180s = 3m, and 30m is declared.
	stub_gh build 6 60
	workflow_with '    timeout-minutes: 30 # budget: p95=600s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"drift-loose"* ]]
	[[ "$output" == *"3m"* ]]
}

@test "a small slack is not drift — a budget is a ceiling, not a target" {
	# Justified 3m, declared 6m: inside the stated slack, so silent.
	stub_gh build 6 60
	workflow_with '    timeout-minutes: 6 # budget: p95=60s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 0 ]
}

@test "a job with fewer than the minimum samples reports unmeasurable, never a number" {
	# The trap this exists for: ten of fourteen jobs run weekly or on release, so
	# a naive p95 would compute a confident value from two samples and propose
	# tightening a release job on it.
	stub_gh build 2 60
	workflow_with '    timeout-minutes: 30 # budget: p95=600s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unmeasurable"* ]]
	[[ "$output" == *"2/5 samples"* ]]
	# It must NOT reach a drift verdict on that sample.
	[[ "$output" != *"drift-"* ]]
}

@test "a grandfathered entry with a usable sample is prompted for conversion" {
	# The ratchet's other end: debt that can now be paid, reported as such rather
	# than silently converted — a bot must not re-baseline the number it defends.
	stub_gh build 6 100
	workflow_with '    timeout-minutes: 15 # budget: grandfathered measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"grandfathered"* ]]
	[[ "$output" == *"convert it"* ]]
	[[ "$output" == *"5m"* ]]
}

@test "a grandfathered entry with too small a sample is unmeasurable, not a conversion prompt" {
	stub_gh build 2 100
	workflow_with '    timeout-minutes: 15 # budget: grandfathered measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unmeasurable"* ]]
	[[ "$output" != *"convert it"* ]]
}

@test "matrix legs pool into one distribution — one timeout bounds them all" {
	# Three legs per run x 2 runs = 6 samples, which clears the minimum even
	# though only two runs exist.
	stub_gh_matrix dist 2 100
	{
		printf 'name: t\non:\n  push:\njobs:\n  dist:\n    runs-on: ubuntu-latest\n'
		printf '    timeout-minutes: 5 # budget: p95=100s x3 measured=2026-08-10\n'
		printf '    strategy:\n      matrix:\n        target: [one, two, three]\n'
		printf '    steps:\n      - run: true\n'
	} >"$WORKFLOWS/t.yml"
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 0 ]
}

@test "a failed API query is exit 2, never a drift verdict" {
	# Reporting a healthy budget as drifted on a network blip is the failure mode
	# that gets a scheduled gate switched off.
	stub_gh build 6 100
	touch "$BATS_TEST_TMPDIR/gh.fails"
	workflow_with '    timeout-minutes: 5 # budget: p95=100s x3 measured=2026-08-10'
	run "$TASK" "$WORKFLOWS"
	[ "$status" -eq 2 ]
}

@test "an absent gh is exit 2, never a pass" {
	printf '#!/usr/bin/env bash\nexit 127\n' >"$STUB/gh"
	chmod +x "$STUB/gh"
	workflow_with '    timeout-minutes: 5 # budget: p95=100s x3 measured=2026-08-10'
	# An empty PATH entry for gh: `command -v` must not find it.
	rm -f "$STUB/gh"
	run env PATH="$STUB:/usr/bin:/bin" "$TASK" "$WORKFLOWS"
	[ "$status" -eq 2 ]
}

@test "a missing workflow directory is exit 2, never a pass" {
	stub_gh build 6 100
	run "$TASK" "$BATS_TEST_TMPDIR/absent"
	[ "$status" -eq 2 ]
}
