#!/usr/bin/env bats
# subject: mise-tasks/merged-pr-keys
#
# CLOUD-814. Every case drives the forge reading through MERGED_PR_KEYS_SOURCE,
# so the suite runs offline with no `gh` and no network — the shape
# `tests/branch-age-check.bats` uses for BRANCH_AGE_PRS.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/merged-pr-keys"
	SRC="$BATS_TEST_TMPDIR/src-$BATS_TEST_NUMBER.json"
	export MERGED_PR_KEYS_SOURCE="$SRC"
	# Well above every fixture's size, so a case that is not ABOUT truncation
	# never trips the cap and reports a refusal it did not mean to exercise.
	export MERGED_PR_KEYS_LIMIT=100
}

# src <json> — the reading a `gh pr list --json number,body` would have returned.
src() { printf '%s' "$1" >"$SRC"; }

@test "a closing keyword in a merged body emits one row" {
	src '[{"number":9,"body":"work\n\nCloses CLOUD-9"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-9	9" ]
}

@test "Fixes and Resolves are claims too" {
	src '[{"number":9,"body":"Fixes CLOUD-1"},{"number":10,"body":"Resolves CLOUD-2"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-1	9"* ]]
	[[ "$output" == *"CLOUD-2	10"* ]]
}

# The whole chain exists to refuse this: CLOUD-480 was swept to In Review on a
# `Refs:` trailer and sat wrong for 4.5 hours.
@test "a Refs: trailer is a mention and emits nothing" {
	src '[{"number":9,"body":"work\n\nRefs: CLOUD-9"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a bare citation in prose emits nothing" {
	src '[{"number":9,"body":"on the newer compiler. That is CLOUD-271'"'"'s shape."}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "several keys in one body emit several rows, all keyed to that PR" {
	src '[{"number":11,"body":"Closes CLOUD-3\nFixes CLOUD-4"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-3	11"* ]]
	[[ "$output" == *"CLOUD-4	11"* ]]
}

@test "a null body is data, not a crash" {
	src '[{"number":12,"body":null},{"number":13,"body":"Closes CLOUD-5"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-5	13" ]
}

@test "two runs over the same reading are byte-identical" {
	src '[{"number":11,"body":"Closes CLOUD-30"},{"number":2,"body":"Closes CLOUD-4"}]'
	run "$TASK"
	local first="$output"
	run "$TASK"
	[ "$output" = "$first" ]
}

# THE MEASURED DEFECT (CLOUD-814). `gh pr list --limit 400` returned exactly 400
# and cut the range at #161, hiding #170/#337/#339. A truncated evidence file is
# an UNDER-report, so landed work reads as live and the drain stops naming it.
@test "a reading at the fetch limit is refused as truncated, not returned short" {
	src '[{"number":9,"body":"Closes CLOUD-9"},{"number":10,"body":"Closes CLOUD-10"}]'
	MERGED_PR_KEYS_LIMIT=2 run "$TASK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"truncated"* ]]
	[[ "$output" != *"CLOUD-9	9"* ]]
}

@test "a reading below the fetch limit is answered" {
	src '[{"number":9,"body":"Closes CLOUD-9"}]'
	MERGED_PR_KEYS_LIMIT=2 run "$TASK"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-9	9" ]
}

@test "an empty forge answer is could-not-look, never an empty evidence file" {
	src '[]'
	run "$TASK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot be true of a repository with a trunk"* ]]
}

@test "an unreadable source is exit 2" {
	MERGED_PR_KEYS_SOURCE="$BATS_TEST_TMPDIR/absent.json" run "$TASK"
	[ "$status" -eq 2 ]
}

@test "a source that is not a JSON array is exit 2" {
	src 'not json'
	run "$TASK"
	[ "$status" -eq 2 ]
}

@test "a non-numeric limit is a caller bug, not a default" {
	src '[{"number":9,"body":"Closes CLOUD-9"}]'
	MERGED_PR_KEYS_LIMIT=lots run "$TASK"
	[ "$status" -eq 2 ]
}

# Rule 4: the keyword lives in the body, and the body must not reach the report.
@test "output carries no PR body" {
	src '[{"number":9,"body":"customer detail here\n\nCloses CLOUD-9"}]'
	run "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"customer detail"* ]]
}
