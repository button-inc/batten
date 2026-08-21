#!/usr/bin/env bats
# subject: mise-tasks/rust-paths-check.sh
# The gate that ships with `rust.yml`'s `paths:` filter (AGENTS.md non-negotiable
# 2). The filter is what makes the four Rust jobs ABSENT rather than `skipped` on
# a diff they cannot judge, and absence is a state `checks-green` accepts by
# design — so a filter that is too narrow does not fail anywhere. It merely lets
# a `windows` regression land with every required check green.
#
# Driven against fixture workflows, so the suite can hold filters the committed
# tree must never carry. The committed file is asserted too.

setup() {
	load helpers
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/rust-paths-check.sh"
	WF="$BATS_TEST_TMPDIR/rust.yml"
	filter '"crates/**"' '"Cargo.toml"' '"Cargo.lock"' '"rust-toolchain*"' \
		'"deny.toml"' '"mise.toml"' '"mise.lock"' '".github/workflows/rust.yml"'
}

# Write a workflow whose pull_request paths list is exactly the arguments.
filter() {
	{
		printf 'on:\n  pull_request:\n    types: [opened]\n    paths:\n'
		for pattern in "$@"; do printf '      - %s\n' "$pattern"; done
		printf 'jobs:\n  cross:\n    name: cross\n'
	} >"$WF"
}

# --- the committed tree ------------------------------------------------------

@test "the committed rust.yml filter honours every probe" {
	run "$CHECK"
	[ "$status" -eq 0 ]
}

# --- pass --------------------------------------------------------------------

@test "the full filter selects every declared input and no docs path" {
	run "$CHECK" "$WF"
	[ "$status" -eq 0 ]
}

@test "a directory glob selects a file below it" {
	# `crates/**` is the pattern the whole split rests on.
	filter '"crates/**"' '"Cargo.toml"' '"Cargo.lock"' '"rust-toolchain*"' \
		'"deny.toml"' '"mise.toml"' '"mise.lock"' '".github/workflows/rust.yml"'
	run "$CHECK" "$WF"
	[ "$status" -eq 0 ]
}

# --- fail: too narrow, which is the silent direction -------------------------

@test "dropping mise.toml is refused, because the jobs run mise tasks" {
	# The input a filter written from the words "the Rust tree" misses first.
	filter '"crates/**"' '"Cargo.toml"' '"Cargo.lock"' '"rust-toolchain*"' \
		'"deny.toml"' '"mise.lock"' '".github/workflows/rust.yml"'
	run "$CHECK" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not select 'mise.toml'"* ]]
	[[ "$output" == *"checks-green"* ]]
}

@test "dropping Cargo.lock is refused" {
	filter '"crates/**"' '"Cargo.toml"' '"rust-toolchain*"' '"deny.toml"' \
		'"mise.toml"' '"mise.lock"' '".github/workflows/rust.yml"'
	run "$CHECK" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Cargo.lock"* ]]
}

# --- fail: too wide, which is only visible as a bill -------------------------

@test "a whole-repository glob is refused" {
	# `**` strips to an empty prefix, so a naive prefix test reads it as matching
	# nothing and passes the widest possible filter as narrow. This row caught
	# exactly that on the matcher's first run.
	filter '"**"'
	run "$CHECK" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *"README.md"* ]]
	[[ "$output" == *"pays for all four jobs"* ]]
}

@test "selecting the memories tree is refused" {
	filter '"crates/**"' '"Cargo.toml"' '"Cargo.lock"' '"rust-toolchain*"' \
		'"deny.toml"' '"mise.toml"' '"mise.lock"' '".github/workflows/rust.yml"' \
		'".serena/**"'
	run "$CHECK" "$WF"
	[ "$status" -eq 1 ]
	[[ "$output" == *".serena/memories/core.md"* ]]
}

# --- could not look: exit 2, never a pass ------------------------------------

@test "a workflow with no paths filter is exit 2, not a pass" {
	# No filter means the workflow runs on every PR — safe, but there is no
	# filter here to judge, and reporting that as honoured would be fiction.
	printf 'on:\n  pull_request:\n    types: [opened]\njobs:\n  cross:\n    name: cross\n' >"$WF"
	run "$CHECK" "$WF"
	[ "$status" -eq 2 ]
	[[ "$output" == *"declares no pull_request"* ]]
}

@test "a pattern the matcher cannot decide is exit 2, not a guess" {
	# A `*` in the middle, a `?`, a character class or a `!` negation all change
	# selection in ways a prefix test gets wrong, and a wrong answer here is the
	# silent false-absent this gate exists to stop.
	filter '"crates/*/src/**"'
	run "$CHECK" "$WF"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot decide"* ]]
}

@test "a missing workflow is exit 2, not a pass" {
	run "$CHECK" "$BATS_TEST_TMPDIR/nope.yml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not found"* ]]
}
