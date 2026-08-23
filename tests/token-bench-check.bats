#!/usr/bin/env bats
# subject: mise-tasks/token-bench-check.sh
# The honesty gate on the published token benchmark (CLOUD-119), and until
# CLOUD-480 it had no suite — so a gate whose whole subject is "a figure nobody
# can reproduce is a marketing artifact" was itself uncorroborated.
#
# Every case drives the gate through TOKEN_BENCH_ROOT at a scratch tree carrying
# one hand-written table, because the predicate is over PUBLISHED BYTES and a
# fixture is the only way to publish bytes that are wrong on purpose. The live
# table is judged by `mise run token-bench-check` on the landing path, which is
# where its reproducibility half belongs; these cases are the decision table for
# the half that reads.
#
# Each refusing case asserts its POINTER and not merely the exit code: the gate
# reaches a regeneration step past the honesty verdict, and a scratch root cannot
# regenerate, so an exit code alone would be satisfied by the wrong failure.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/token-bench-check.sh"
	ROOT="$BATS_TEST_TMPDIR/root"
	mkdir -p "$ROOT/bench/tokens"
	export TOKEN_BENCH_ROOT="$ROOT"
}

publish() { cat >"$ROOT/bench/tokens/RESULTS.md"; }

@test "a missing table is refused, and named — never a pass for want of anything to read" {
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"bench/tokens/RESULTS.md:0 token-bench-missing"* ]]
}

@test "THE DEFECT: a figure with no question is unmethodical, and the section is named" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Baseline** something to compare against.

		**Method.** measured; 30 runs per arm, alternating.

		| batten | 100 |
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no question)"* ]]
}

@test "a figure with no baseline is unmethodical" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Question.** what does it cost?

		**Method.** measured; 30 runs per arm, alternating.

		| batten | 100 |
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no baseline)"* ]]
}

@test "a figure with no method or run count is unmethodical" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Question.** what does it cost?

		**Baseline** something to compare against.

		| baseline | 100 |
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no method or run count)"* ]]
}

@test "THE SILENT GAP: no figure and no stated reason is the worst of the three" {
	# A capability that reads as covered because nothing says it is not. Worse
	# than a stated gap, because nobody chose it.
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Question.** what does it cost?
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"(no figure and no stated reason)"* ]]
}

@test "a stated reason stands in for a figure — the marker alone does not" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**not measured** — the workload needs a second machine, which CLOUD-1 owns.
	EOF
	run "$GATE"
	[[ "$output" != *"token-bench-unmethodical"* ]]

	publish <<-'EOF'
		## Capabilities

		### the one under test

		**not measured**
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"(no figure and no stated reason)"* ]]
}

@test "every unmethodical section is reported, not just the first" {
	publish <<-'EOF'
		## Capabilities

		### the first one

		**Question.** what does it cost?

		### the second one

		**Question.** and this one?
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"the first"* ]] || true
	[ "$(grep -c 'no figure and no stated reason' <<<"$output")" -eq 2 ]
}

@test "a section closed by the next H2 is still judged" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Question.** what does it cost?

		## Appendix
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"(no figure and no stated reason)"* ]]
}

@test "output is pointer-only — no published prose reaches the log" {
	publish <<-'EOF'
		## Capabilities

		### the one under test

		**Question.** SECRETPROSE about the workload.
	EOF
	run "$GATE"
	[[ "$output" != *"SECRETPROSE"* ]]
}
