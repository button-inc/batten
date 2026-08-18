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
	RENOVATE="$BATS_TEST_TMPDIR/renovate.json5"
	# The third path (CLOUD-658) is written by default, for the reason the fixture
	# pairs above are: every row not about it must satisfy it, so only its own
	# rows overwrite this.
	renovate 1.97
}

manifest() { printf '[workspace.package]\nrust-version = "%s"\n' "$1" >"$MANIFEST"; }
tools() { printf '[tools]\nrust = { version = "%s", components = "rustfmt,clippy" }\n' "$1" >"$TOOLS"; }
renovate() {
	printf '{\n  $schema: "https://docs.renovatebot.com/renovate-schema.json",\n  enabledManagers: ["mise", "cargo"],\n  constraints: { rust: "%s" },\n}\n' "$1" >"$RENOVATE"
}
gate() { "$GATE" --manifest "$MANIFEST" --tools "$TOOLS" --renovate "$RENOVATE"; }

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
	run "$GATE" --manifest "$MANIFEST" --tools "$BATS_TEST_TMPDIR/absent.toml" --renovate "$RENOVATE"
	[ "$status" -eq 2 ]
}

# --- the third path: Renovate's hand-written constraint (CLOUD-658) -----------
#
# Renovate's cargo updater does not read `rust-version` (renovatebot/renovate
# #26314, open), so handing `cargo` to it means writing the floor a third time.
# CLOUD-593's argument is what makes that safe: a copy is not the defect, an
# UNGATED copy is. These rows are the gate.

@test "all three agreeing passes" {
	manifest 1.97
	tools 1.97.1
	renovate 1.97
	run gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"constraints.rust"* ]]
}

@test "a Renovate constraint naming a different compiler is refused" {
	# The row the third path exists for: the manifest and the pin agree, so every
	# check that predates CLOUD-658 is green, and MSRV-aware resolution is
	# nonetheless pinned to a compiler this repo stopped building with.
	manifest 1.97
	tools 1.97.1
	renovate 1.85
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"1.85"* ]]
	[[ "$output" == *"1.97.1"* ]]
}

@test "a constraint ahead of the pin is refused too — equality, not a bound" {
	manifest 1.97
	tools 1.97.1
	renovate 1.99
	run gate
	[ "$status" -eq 1 ]
}

@test "a patch component in the constraint is agreement, not drift" {
	# Same reasoning as the manifest row: the comparison is major.minor.
	manifest 1.97
	tools 1.97.1
	renovate 1.97.4
	run gate
	[ "$status" -eq 0 ]
}

@test "a rust key outside the constraints block cannot answer for it" {
	# The Renovate config discusses the pin at length in its comments, and names
	# other `rust`-ish keys nowhere else. Reading the file at large would let a
	# comment satisfy the gate, which is satisfying it by deleting the value.
	manifest 1.97
	tools 1.97.1
	printf '{\n  // constraints: { rust: "1.97" } was here once\n  enabledManagers: ["cargo"],\n  packageRules: [{ matchManagers: ["cargo"], rust: "1.97" }],\n}\n' >"$RENOVATE"
	run gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"no constraints.rust"* ]]
}

@test "a missing constraints.rust is exit 2, never a silent pass" {
	# An absent constraint is MSRV-aware resolution switched off, not a neutral
	# omission — Renovate has nothing else to read it from.
	manifest 1.97
	tools 1.97.1
	printf '{\n  enabledManagers: ["mise", "cargo"],\n}\n' >"$RENOVATE"
	run gate
	[ "$status" -eq 2 ]
}

@test "an unreadable renovate config is exit 2 on the same terms as the other two" {
	manifest 1.97
	tools 1.97.1
	run "$GATE" --manifest "$MANIFEST" --tools "$TOOLS" --renovate "$BATS_TEST_TMPDIR/absent.json5"
	[ "$status" -eq 2 ]
}

@test "the real tree agrees" {
	# The one row that reads the committed files. It is the acceptance criterion
	# stated as a test: whatever the pin is, both derived copies track it.
	run "$GATE" --manifest "$BATS_TEST_DIRNAME/../Cargo.toml" --tools "$BATS_TEST_DIRNAME/../mise.toml" \
		--renovate "$BATS_TEST_DIRNAME/../renovate.json5"
	[ "$status" -eq 0 ]
}
