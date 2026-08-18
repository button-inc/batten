#!/usr/bin/env bats
# CLOUD-593. An MSRV cap lives in two files — the manifest bound and the
# dependabot `ignore:` entry mirroring it — and nothing kept them in step.
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
	BOT="$BATS_TEST_TMPDIR/dependabot.yml"
}

# `deps <spec>...` writes a [workspace.dependencies] table verbatim.
deps() {
	printf '[workspace.dependencies]\n' >"$MANIFEST"
	local spec
	for spec in "$@"; do printf '%s\n' "$spec" >>"$MANIFEST"; done
}
# `ignores <crate>...` writes a cargo entry with an ignore: block.
ignores() {
	printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: "/"\n' >"$BOT"
	if [ "$#" -gt 0 ]; then
		printf '    ignore:\n' >>"$BOT"
		local c
		for c in "$@"; do printf '      - dependency-name: %s\n        versions: [">= 9.9.9"]\n' "$c" >>"$BOT"; done
	fi
	printf '    groups:\n      cargo:\n        patterns: ["*"]\n' >>"$BOT"
}
gate() { "$GATE" --manifest "$MANIFEST" --dependabot "$BOT"; }

@test "both sets empty passes — the state CLOUD-593 leaves, and the ratchet still runs" {
	deps 'ignore = { version = ">=0.4.23", default-features = false }'
	ignores
	run gate
	[ "$status" -eq 0 ]
}

@test "a cap mirrored by an ignore entry passes" {
	deps 'ignore = { version = ">=0.4.23, <0.4.30", default-features = false }'
	ignores ignore
	run gate
	[ "$status" -eq 0 ]
}

@test "THE HALF-LIFT: an ignore entry with no cap is refused, and named" {
	# The direction with no symptom. Nothing else in the repo goes red on this.
	deps 'ignore = { version = ">=0.4.23", default-features = false }'
	ignores ignore
	run gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"ignore"* ]]
	[[ "$output" == *"half-lift"* ]]
}

@test "a cap with no ignore entry is refused, and named" {
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
	# a dependabot entry for nearly every dependency in the file.
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

@test "a dependency-name outside the ignore: block is not read as a cap mirror" {
	deps 'serde = "1"'
	printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n    allow:\n      - dependency-name: serde\n    groups:\n      cargo:\n        patterns: ["*"]\n' >"$BOT"
	run gate
	[ "$status" -eq 0 ]
}

@test "an unreadable file is exit 2 — never a silent agreement" {
	deps 'serde = "1"'
	run "$GATE" --manifest "$MANIFEST" --dependabot "$BATS_TEST_TMPDIR/absent.yml"
	[ "$status" -eq 2 ]
}

@test "the real tree agrees" {
	run "$GATE" --manifest "$BATS_TEST_DIRNAME/../Cargo.toml" --dependabot "$BATS_TEST_DIRNAME/../.github/dependabot.yml"
	[ "$status" -eq 0 ]
}
