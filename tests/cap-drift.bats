#!/usr/bin/env bats
# CLOUD-593. An MSRV cap lives in two files — the manifest bound and the bot-side
# rule mirroring it — and nothing kept them in step. The bot side is
# `renovate.json5`'s `packageRules[].allowedVersions` since CLOUD-660 retired
# Dependabot and deleted the `ignore:` list this suite used to write.
#
# THE ROW THAT MATTERS IS `ignore-without-cap`, and it is the reason this gate
# exists rather than a one-sided check. Lift the manifest cap alone and every
# other gate is green: the manifest admits 0.4.33, the bot still withholds it,
# nothing proposes it ever again, and no check anywhere is red. The freeze
# survives the change that was supposed to end it. The opposite direction has a
# symptom of its own — CI reddens the way CLOUD-344 measured — so a suite that
# only covered it would pass on the half-lift.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/cap-drift"
	MANIFEST="$BATS_TEST_TMPDIR/Cargo.toml"
	BOT="$BATS_TEST_TMPDIR/renovate.json5"
}

# `deps <spec>...` writes a [workspace.dependencies] table verbatim.
deps() {
	printf '[workspace.dependencies]\n' >"$MANIFEST"
	local spec
	for spec in "$@"; do printf '%s\n' "$spec" >>"$MANIFEST"; done
}
# `ignores <crate>...` writes a Renovate config whose `packageRules` withhold
# each named crate with `allowedVersions`. The first rule is always a grouping
# rule carrying `matchPackageNames` and NO `allowedVersions`, so every case also
# exercises the scoping: a name matched for grouping withholds nothing.
ignores() {
	{
		printf '{\n  packageRules: [\n'
		printf '    { matchPackageNames: ["grouped-only"], groupName: "cargo" },\n'
		local c
		for c in "$@"; do
			printf '    {\n      matchPackageNames: ["%s"],\n      allowedVersions: "<9.9.9",\n    },\n' "$c"
		done
		printf '  ],\n}\n'
	} >"$BOT"
}
gate() { "$GATE" --manifest "$MANIFEST" --renovate "$BOT"; }

@test "both sets empty passes — the state CLOUD-593 leaves, and the ratchet still runs" {
	deps 'ignore = { version = ">=0.4.23", default-features = false }'
	ignores
	run gate
	[ "$status" -eq 0 ]
}

@test "a cap mirrored by an allowedVersions rule passes" {
	deps 'ignore = { version = ">=0.4.23, <0.4.30", default-features = false }'
	ignores ignore
	run gate
	[ "$status" -eq 0 ]
}

@test "THE HALF-LIFT: an allowedVersions rule with no cap is refused, and named" {
	# The direction with no symptom. Nothing else in the repo goes red on this.
	deps 'ignore = { version = ">=0.4.23", default-features = false }'
	ignores ignore
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"ignore"* ]]
	[[ "$output" == *"half-lift"* ]]
}

@test "a cap with no allowedVersions rule is refused, and named" {
	deps 'globset = { version = ">=0.4.15, <0.4.20", default-features = false }'
	ignores
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"globset"* ]]
}

@test "both directions are reported in one pass, not one per run" {
	deps 'globset = { version = ">=0.4.15, <0.4.20", default-features = false }'
	ignores ignore
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"globset"* ]]
	[[ "$output" == *"ignore"* ]]
}

@test "a caret requirement is not a cap — it bounds the major, not the compiler" {
	# The narrowing that keeps this usable. Treating `"0.4"` as a cap would demand
	# a bot-side rule for nearly every dependency in the file.
	deps 'serde = { version = "1", default-features = false }' 'toml = "0.9"'
	ignores
	run gate
	[ "$status" -eq 0 ]
}

@test "a bare-string upper bound is a cap too, not only the inline-table form" {
	deps 'foo = ">=1.0, <2.0"'
	ignores
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"foo"* ]]
}

@test "a less-than outside the workspace dependencies table mints no phantom cap" {
	printf '[workspace.package]\nversion = "0.1.0"\n\n[workspace.dependencies]\nserde = "1"\n\n[other]\nthing = "<1.0"\n' >"$MANIFEST"
	ignores
	run gate
	[ "$status" -eq 0 ]
}

@test "a matchPackageNames used for grouping is not read as a cap mirror" {
	deps 'serde = "1"'
	printf '{\n  packageRules: [\n    { matchPackageNames: ["serde"], groupName: "cargo" },\n  ],\n}\n' >"$BOT"
	run gate
	[ "$status" -eq 0 ]
}

@test "an allowedVersions named only in a comment mirrors nothing" {
	# `//` comments are stripped first, for `ci-local-parity`'s reason: a gate a
	# comment can satisfy is a gate satisfied by deleting the key it explains.
	deps 'serde = { version = ">=1, <2" }'
	printf '{\n  packageRules: [\n    // { matchPackageNames: ["serde"], allowedVersions: "<2" },\n  ],\n}\n' >"$BOT"
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"serde"* ]]
}

@test "a rule written inline reads the same as one spread over lines" {
	deps 'serde = { version = ">=1, <2" }'
	printf '{\n  packageRules: [{ matchPackageNames: ["serde"], allowedVersions: "<2" }],\n}\n' >"$BOT"
	run gate
	[ "$status" -eq 0 ]
}

@test "an unreadable file is exit 2 — never a silent agreement" {
	deps 'serde = "1"'
	run "$GATE" --manifest "$MANIFEST" --renovate "$BATS_TEST_TMPDIR/absent.json5"
	[ "$status" -eq 2 ]
}

@test "the real tree agrees" {
	run "$GATE" --manifest "$BATS_TEST_DIRNAME/../Cargo.toml" --renovate "$BATS_TEST_DIRNAME/../renovate.json5"
	[ "$status" -eq 0 ]
}
