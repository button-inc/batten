#!/usr/bin/env bats
# CLOUD-395. `cross-check` carries this repository's cross-platform claim, and
# for its whole life it checked only half of what it claimed: `cargo check`
# without `--all-targets` compiles the default target set — lib and bins — and
# no `#[cfg(test)]` module, nothing under `tests/`.
#
# The half it skipped is the half most likely to break. Platform-specific code
# in the library is deliberate and already `#[cfg(unix)]`-gated; test code
# reaches for `PermissionsExt`, `#!/bin/sh` fixtures and Unix paths as a matter
# of course, so a suite could go un-portable for months with every gate green.
#
# Asserted over the committed task body, not over a run. A green `cross-check`
# cannot tell the two coverages apart — that is exactly how the narrower one
# survived — so the flag itself is the predicate, the shape
# `tests/task-fail-closed.bats` uses for the same reason.

setup() {
	MANIFEST="$BATS_TEST_DIRNAME/../mise.toml"
}

# The body of `[tasks.cross-check]`, bounded by the next table header so a
# later task's `cargo check` cannot be read as this one's.
cross_check_body() {
	awk '/^\[tasks\.cross-check\]/{p=1;next} /^\[tasks\./{p=0} p' "$MANIFEST"
}

@test "cross-check type-checks test code, not only the library and bins" {
	local body
	body=$(cross_check_body)
	[ -n "$body" ]

	# Executable lines only: this task's comments discuss the flag at length, and
	# a gate that passes on its own documentation is not a gate.
	local code
	code=$(grep -vE '^[[:space:]]*#' <<<"$body")

	local checks
	checks=$(grep -E 'cargo check' <<<"$code")
	[ -n "$checks" ]
	# Every `cargo check` in the body, not merely one of them — a second triple
	# added later must carry the same coverage.
	local line
	while IFS= read -r line; do
		[[ "$line" == *"--all-targets"* ]]
	done <<<"$checks"
}

@test "the check is still target-scoped, so the flag widened coverage rather than replacing it" {
	local code
	code=$(grep -vE '^[[:space:]]*#' <<<"$(cross_check_body)")
	local line
	while IFS= read -r line; do
		[[ "$line" == *"--target"* ]]
		[[ "$line" == *"--workspace"* ]]
	done <<<"$(grep -E 'cargo check' <<<"$code")"
}

@test "it stays a check, never a build — no linker and no SDK for a foreign triple" {
	# `cargo check` stops at codegen-to-metadata, which is what makes
	# cross-platform coverage affordable on a Linux runner at all. A `cargo build`
	# or `cargo test` here would need a target linker, and the Darwin triples'
	# real link is `darwin-link`'s job by design.
	local code
	code=$(grep -vE '^[[:space:]]*#' <<<"$(cross_check_body)")
	! grep -qE 'cargo (build|test|run)' <<<"$code"
}

@test "cross-check denies warnings, so a dead cfg-gated helper fails rather than prints" {
	# CLOUD-397. `--all-targets` made the test code visible to this gate; warnings
	# being tolerated is what let its one finding sit unread on every run. The flag
	# is the predicate and not the run's exit code, because a green run cannot
	# distinguish "no warnings" from "warnings tolerated" — which is precisely how
	# this went unnoticed for as long as it did.
	local code
	code=$(grep -vE '^[[:space:]]*#' <<<"$(cross_check_body)")

	local line
	while IFS= read -r line; do
		[[ "$line" == *"RUSTFLAGS="* ]]
		[[ "$line" == *"-D warnings"* ]]
	done <<<"$(grep -E 'cargo check' <<<"$code")"
}
