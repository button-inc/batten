#!/usr/bin/env bats
# CLOUD-593. The floor is a derived copy of the toolchain pin, so the two must
# agree — and this gate REPLACES `mise run msrv`, which answered the same
# question by compiling the workspace a second time at a second toolchain.
#
# Driven at fixtures rather than the real tree, for the reason `ci-tools-check`
# gives: the decision is the part worth testing, and it only tests if the suite
# can point it at drift the real tree must never have.
#
# The rows are written so that a gate comparing the two strings RAW passes the
# agreement row and fails the patch row — that spelling is the plausible wrong
# one, and it would redden on every patch bump of the pin, which is the
# false-positive rate that gets a gate switched off.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/msrv-pin-agreement"
	MANIFEST="$BATS_TEST_TMPDIR/Cargo.toml"
	TOOLS="$BATS_TEST_TMPDIR/mise.toml"
}

manifest() { printf '[workspace.package]\nrust-version = "%s"\n' "$1" >"$MANIFEST"; }
tools() { printf '[tools]\nrust = { version = "%s", components = "rustfmt,clippy" }\n' "$1" >"$TOOLS"; }
gate() { "$GATE" --manifest "$MANIFEST" --tools "$TOOLS"; }

@test "the floor and the pin agreeing passes" {
	manifest 1.97
	tools 1.97.1
	run gate
	[ "$status" -eq 0 ]
}

@test "the floor behind the pin is refused, and both values are named" {
	# The defect exactly: 1.85 against a pin that moved to 1.97.
	manifest 1.85
	tools 1.97.1
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"1.85"* ]]
	[[ "$output" == *"1.97.1"* ]]
}

@test "the floor ahead of the pin is refused too — the check is equality, not a bound" {
	# A floor above the pin is not conservative, it is a manifest that refuses to
	# resolve for the compiler this repo actually builds with.
	manifest 1.99
	tools 1.97.1
	run gate
	[ "$status" -eq 1 ]
}

@test "a patch-only difference is agreement, not drift" {
	# THE ROW THAT REFUSES A RAW STRING COMPARISON. `rust-version` is a minimum
	# and carries no patch component; demanding "1.97.1" there would claim a
	# precision the field does not have, and redden on every patch bump.
	manifest 1.97
	tools 1.97.3
	run gate
	[ "$status" -eq 0 ]
}

@test "a bare string pin is read, not only the inline-table form" {
	manifest 1.97
	printf '[tools]\nrust = "1.97.1"\n' >"$TOOLS"
	run gate
	[ "$status" -eq 0 ]
}

@test "a rust-version inside another table cannot answer for the workspace" {
	# Anchored at line start: an indented `rust-version` under a dependency entry
	# is not the workspace's declaration, and reading it would let a dependency
	# silently satisfy this gate.
	printf '[workspace.package]\nrust-version = "1.85"\n\n[workspace.dependencies]\nfoo = { version = "1", rust-version = "1.97" }\n' >"$MANIFEST"
	tools 1.97.1
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"1.85"* ]]
}

@test "a manifest with no rust-version is exit 2, never a silent pass" {
	printf '[workspace.package]\nversion = "0.1.0"\n' >"$MANIFEST"
	tools 1.97.1
	run gate
	[ "$status" -eq 2 ]
}

@test "a tools file with no rust pin is exit 2, never a silent pass" {
	manifest 1.97
	printf '[tools]\nhk = "1.54.0"\n' >"$TOOLS"
	run gate
	[ "$status" -eq 2 ]
}

@test "an unreadable file is exit 2 — a gate that cannot look must not report agreement" {
	manifest 1.97
	run "$GATE" --manifest "$MANIFEST" --tools "$BATS_TEST_TMPDIR/absent.toml"
	[ "$status" -eq 2 ]
}

@test "the real tree agrees" {
	# The one row that reads the committed files. It is the acceptance criterion
	# stated as a test: whatever the pin is, the floor tracks it.
	run "$GATE" --manifest "$BATS_TEST_DIRNAME/../Cargo.toml" --tools "$BATS_TEST_DIRNAME/../mise.toml"
	[ "$status" -eq 0 ]
}
