#!/usr/bin/env bats
# CLOUD-404. The gate that stops a pin sliding back behind the toolchain install
# action's download retry.
#
# Driven entirely through fixture workflows passed as arguments, so the suite
# judges its own files rather than the repository's — which is what lets it assert
# a FAILING tree without the repo having to contain one, and keeps it green when
# the real pin moves forward.
#
# The two shas are written out in full, once each, because `attribution-check`
# exempts a pinned coordinate and refuses a bare vendor name in prose — and
# because a truncated sha would not exercise the 40-hex pattern the gate matches.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/mise-action-floor"
	WF="$BATS_TEST_TMPDIR/wf"
	mkdir -p "$WF"
}

# The pin that predates the retry: v4.2.4, and what the floating `v4` tag still
# resolves to — so this is the reachable backslide, not an invented one.
PRE_RETRY='jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654'
# The commit that introduced `retryDownload`, which ships its own built dist.
WITH_RETRY='jdx/mise-action@9dda3952d607125725deac9ec10a5f0e245d266b'

# A one-job workflow whose install step uses the given coordinate.
workflow() {
	local file=$1 uses=$2
	{
		printf 'name: %s\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n' "$file"
		printf '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n'
		printf '      - uses: %s\n' "$uses"
	} >"$WF/$file.yml"
}

@test "a pin carrying the retry passes, and says what it judged" {
	workflow ci "$WITH_RETRY"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 pin(s)"* ]]
	[[ "$output" == *"none predating"* ]]
}

@test "THE ACCEPTANCE CASE: a pre-retry pin fails and is named with path:line" {
	workflow ci "$PRE_RETRY"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci.yml:9"* ]]
	[[ "$output" == *"predates the download retry"* ]]
}

@test "THE BACKSLIDE: one reverted pin among many still fails" {
	# The exact shape Dependabot would produce, and the one a "does any good pin
	# exist" predicate would pass. `auto-dependabot-land` lands bot bumps with no
	# human in the loop, so this case is the whole reason the gate exists.
	workflow a "$WITH_RETRY"
	workflow b "$WITH_RETRY"
	workflow c "$PRE_RETRY"
	run "$TASK" "$WF/a.yml" "$WF/b.yml" "$WF/c.yml"
	[ "$status" -eq 1 ]
	[[ "$output" == *"c.yml:9"* ]]
	[[ "$output" == *"1 of 3"* ]]
	# Named the offender only — a gate that reports the innocent files too is one
	# whose output stops being read.
	[[ "$output" != *"a.yml"* ]]
}

@test "SHOWN ABLE TO FAIL IN BOTH DIRECTIONS: every pin reverted fails with the full count" {
	workflow a "$PRE_RETRY"
	workflow b "$PRE_RETRY"
	run "$TASK" "$WF/a.yml" "$WF/b.yml"
	[ "$status" -eq 1 ]
	[[ "$output" == *"2 of 2"* ]]
}

@test "the predicate is scoped to this action, so a lookalike coordinate does not fire" {
	# The same sha on a different action is not this defect. A gate firing on a
	# lookalike trains its readers to ignore it.
	workflow ci "$WITH_RETRY"
	printf '      - uses: some/other-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654\n' >>"$WF/ci.yml"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 0 ]
}

@test "the sha in prose or a comment is not a pin" {
	workflow ci "$WITH_RETRY"
	printf '      # was 7e36c90d9ab29c415a2384db3006f3ec8a8cc654 before CLOUD-404\n' >>"$WF/ci.yml"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 0 ]
}

@test "ANTI-VACUITY: a workflow with no mise-action pin is exit 2, never a pass" {
	# `ci-tools-check`'s refusal, for the same reason: the thing under test must
	# not be able to vanish and read as clean.
	workflow ci 'actions/setup-node@1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a'
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"pin found"* ]]
}

@test "an unversioned float is not a pin this gate can judge, so it is exit 2" {
	# `@v4` carries no sha, so the denylist cannot speak about it at all. Reporting
	# green over it would be a claim the gate cannot support.
	workflow ci "${WITH_RETRY%@*}@v4"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 2 ]
}

@test "COULD NOT LOOK: a missing path is exit 2 rather than an empty pass" {
	run "$TASK" "$WF/absent.yml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not found"* ]]
}

@test "POINTER, NEVER PAYLOAD: the report carries no workflow content" {
	workflow ci "$PRE_RETRY"
	run "$TASK" "$WF/ci.yml"
	[ "$status" -eq 1 ]
	[[ "$output" != *"runs-on"* ]]
	[[ "$output" != *"ubuntu-latest"* ]]
	[[ "$output" != *"actions/checkout"* ]]
}
