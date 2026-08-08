#!/usr/bin/env bats
#
# The gate with no false negatives: it links the Darwin targets rather than
# type-checking them, so a dependency needing an Apple SDK fails here instead of
# in the release workflow after a tag is cut.

setup() {
	LINK="${BATS_TEST_DIRNAME}/../mise-tasks/darwin-link"
	cd "${BATS_TEST_DIRNAME}/.." || return 1
}

@test "a non-darwin target is refused" {
	run "$LINK" x86_64-unknown-linux-gnu
	[ "$status" -ne 0 ]
	[[ "$output" == *"expected an *-apple-darwin target"* ]]
}

@test "it links rather than type-checks" {
	# `cargo check` would defeat the entire point: it never invokes the linker,
	# so it cannot see a missing system framework.
	# Comment lines are excluded: the script's prose explains why `cargo check`
	# is insufficient, and matching that would assert the opposite of the point.
	run bash -c "grep -v '^[[:space:]]*#' '$LINK' | grep -c 'cargo zigbuild'"
	[ "$output" -ge 1 ]
	run bash -c "grep -v '^[[:space:]]*#' '$LINK' | grep -c 'cargo check'"
	[ "$output" -eq 0 ]
}

@test "it mutates the toolchain only through the target-ensure lock" {
	# A bare `rustup target add` here raced the concurrent doctor and both
	# rolled back (CLOUD-220); the sweep in target-ensure.bats holds the whole
	# task layer to one live call site, this pins the script that regressed.
	run bash -c "grep -v '^[[:space:]]*#' '$LINK' | grep -c 'rustup target add'"
	[ "$output" -eq 0 ]
	run bash -c "grep -v '^[[:space:]]*#' '$LINK' | grep -c 'target-ensure'"
	[ "$output" -ge 1 ]
}

@test "it does not build the optimized profile" {
	# Linking is what is under test; an LTO release build would prove nothing
	# extra and would put this leg over the CI critical path it must hide under.
	run bash -c "grep -v '^[[:space:]]*#' '$LINK' | grep -c 'profile dist'"
	[ "$output" -eq 0 ]
}
