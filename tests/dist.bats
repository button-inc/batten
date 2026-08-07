#!/usr/bin/env bats
#
# The `dist` task's contract. The archive NAME is the part other things depend
# on — CLOUD-65's `cargo binstall` path resolves a release asset by name — so the
# naming and per-platform format rules are pinned here rather than left to
# whatever the script happened to emit on the last release.
#
# These exercise the pure decisions (naming, format selection, argument
# handling). The build itself is not run here: a real cross-build needs the
# target toolchain installed and takes minutes, and the first release is its
# end-to-end proof.

setup() {
	DIST="${BATS_TEST_DIRNAME}/../mise-tasks/dist"
	# Source the script's functions without running main: everything below main
	# is pure, and `main "$@"` with no args would exit 1.
	# shellcheck disable=SC1090
	eval "$(sed '/^main "\$@"$/d' "$DIST")"
}

@test "windows targets are detected by triple, not by host" {
	run is_windows_target x86_64-pc-windows-msvc
	[ "$status" -eq 0 ]
	run is_windows_target x86_64-pc-windows-gnu
	[ "$status" -eq 0 ]
}

@test "unix targets are not windows targets" {
	for target in x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin; do
		run is_windows_target "$target"
		[ "$status" -ne 0 ]
	done
}

@test "archive stem is name-vversion-target" {
	run archive_stem 1.2.3 x86_64-unknown-linux-gnu
	[ "$status" -eq 0 ]
	[ "$output" = "batten-v1.2.3-x86_64-unknown-linux-gnu" ]
}

@test "archive stem carries the target, so two targets never collide" {
	a=$(archive_stem 0.1.0 aarch64-apple-darwin)
	b=$(archive_stem 0.1.0 x86_64-apple-darwin)
	[ "$a" != "$b" ]
}

@test "the version comes from Cargo.toml, never from an argument" {
	cd "${BATS_TEST_DIRNAME}/.." || return 1
	run crate_version
	[ "$status" -eq 0 ]
	# Whatever the workspace currently declares — asserted as a shape, so a
	# version bump does not break the test.
	[[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]
}

@test "a missing version in Cargo.toml is an error, not an empty name" {
	cd "$BATS_TEST_TMPDIR" || return 1
	echo '[workspace]' >Cargo.toml
	run crate_version
	[ "$status" -ne 0 ]
	[[ "$output" == *"could not read version"* ]]
}

@test "no target argument is a usage error" {
	run "$DIST"
	[ "$status" -ne 0 ]
	[[ "$output" == *"usage: mise run dist"* ]]
}

@test "--help succeeds and does not build" {
	run "$DIST" --help
	[ "$status" -eq 0 ]
	[[ "$output" == *"usage: mise run dist"* ]]
}

@test "an unknown build tool is refused before anything is compiled" {
	cd "${BATS_TEST_DIRNAME}/.." || return 1
	DIST_BUILD_TOOL=bogus run "$DIST" x86_64-unknown-linux-gnu
	[ "$status" -ne 0 ]
	[[ "$output" == *"must be cargo, cross, or zigbuild"* ]]
}
