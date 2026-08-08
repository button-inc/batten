#!/usr/bin/env bats
# completions-check's decision table (CLOUD-27): does every committed completion
# script still match what the binary emits from its surface?
#
# The gate has to run `cargo run`, so a fixture cannot be a bare directory — it
# needs a real workspace. Each fixture is therefore a scratch root that symlinks
# the manifest and sources of the real repo and holds its *own* copy of
# `completions/`, which is the only thing a test mutates. CARGO_TARGET_DIR points
# back at the real target dir so the fixture compiles nothing the suite has not
# already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/completions-check"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp -R "$REPO/completions" "$ROOT/completions"
	export COMPLETIONS_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "committed completions matching the surface exit 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every committed completion matches the surface"* ]]
}

@test "a drifted completion is reported with a pointer" {
	printf 'complete -c batten -l invented-flag\n' >>"$ROOT/completions/batten.fish"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"completions/batten.fish:0 completions-drift"* ]]
}

@test "a missing completion is reported rather than silently skipped" {
	# The failure this catches: a shell dropped from the committed set while the
	# loop still claims to cover it. Absent must be a violation, never a no-op.
	rm -f "$ROOT/completions/batten.zsh"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"completions/batten.zsh:0 completions-missing"* ]]
}

@test "output is pointer-only — no completion script body echoed" {
	printf 'complete -c batten -l a-very-distinctive-invented-flag\n' >>"$ROOT/completions/batten.fish"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"a-very-distinctive-invented-flag"* ]]
}

@test "the gate leaves the tree it judges unmodified" {
	# A gate that rewrites what it is judging cannot fail twice: the second run
	# would pass, laundering the drift into a clean result.
	printf 'complete -c batten -l invented-flag\n' >>"$ROOT/completions/batten.fish"
	before="$(cat "$ROOT/completions/batten.fish")"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(cat "$ROOT/completions/batten.fish")" = "$before" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "this repo's committed completions match its surface — the gate on the real tree" {
	# The self-consumption case: run against the actual repository, so the suite
	# also asserts the committed artifact is current.
	unset COMPLETIONS_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}
