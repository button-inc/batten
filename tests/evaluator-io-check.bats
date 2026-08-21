#!/usr/bin/env bats
# The decision `evaluator-io-check` makes is ONE THING — the inversion — and this
# suite is over that decision rather than over a two-minute rebuild.
#
# `EVALUATOR_IO_PROBE_CMD` stands in for the probe build, which is what lets both
# verdicts be exercised in milliseconds. The real build is what the task runs in
# the gate; what a suite has to prove is that the task reads its result the right
# way round, and that is the half a rebuild would tell you nothing extra about.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/evaluator-io-check"
}

# THE LOAD-BEARING CASE. A probe build in which the test PASSES means the test
# stayed green with `http` on — it discriminates nothing. Reading that as success
# is the single mistake this gate exists to not make, and it is the mistake a
# gate written without thinking about the inversion makes by default.
@test "a probe build in which the test PASSES is the finding, not a pass" {
	EVALUATOR_IO_PROBE_CMD="true" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"does not discriminate"* ]]
	[[ "$output" == *"no_evaluator_feature_admits_io"* ]]
}

@test "a probe build in which the test FAILS is the pass" {
	EVALUATOR_IO_PROBE_CMD="$BATS_TEST_DIRNAME/fixtures/evaluator-io/failing-probe" run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"goes red under"* ]]
}

# THE OTHER LOAD-BEARING CASE, and the one a gate written to the obvious shape
# gets wrong. `cargo test` exits non-zero for a compile error too — and reading
# THAT as "the probe falsified the assertion" gives the gate a pass it did not
# earn, one that gets more likely the more broken the crate is. Could-not-look
# is exit 1, never the verdict.
@test "a probe build that failed to COMPILE is could-not-look, not the pass" {
	EVALUATOR_IO_PROBE_CMD="$BATS_TEST_DIRNAME/fixtures/evaluator-io/broken-build" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"did not run"* ]]
	[[ "$output" != *"goes red under"* ]]
}

# The same distinction from the other side: a probe run where some OTHER test
# panicked and the named one never ran is not this gate's evidence either.
@test "a probe build where the named test never ran is could-not-look" {
	EVALUATOR_IO_PROBE_CMD="$BATS_TEST_DIRNAME/fixtures/evaluator-io/other-test-failed" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"did not run"* ]]
}

# Rule 4. The probe build's output carries module bodies, file paths and a
# backtrace; none of it may reach this gate's stdout. The stub prints a line that
# would be unmistakable if it leaked.
@test "the probe build's own output never reaches the gate's output" {
	EVALUATOR_IO_PROBE_CMD="$BATS_TEST_DIRNAME/fixtures/evaluator-io/noisy-probe" run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"deny contains"* ]]
	[[ "$output" != *"POLICY-BODY-LEAKED"* ]]
}
