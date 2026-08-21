#!/usr/bin/env bats
# subject: mise-tasks/schema-check.sh
# schema-check's decision table (CLOUD-33): does the committed JSON Schema still
# match what the binary derives from the config types?
#
# The gate runs `cargo run`, so a fixture cannot be a bare directory — it needs a
# real workspace. Each fixture is a scratch root that symlinks the manifest and
# sources of the real repo and holds its *own* copy of `schema/`, which is the
# only thing a test mutates. CARGO_TARGET_DIR points back at the real target dir
# so the fixture compiles nothing the suite has not already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/schema-check.sh"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp -R "$REPO/schema" "$ROOT/schema"
	export SCHEMA_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "a committed schema matching the config types exits 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"match the config types"* ]]
}

# The override surface is a SECOND artifact with its own derivation (CLOUD-239).
# Checking only the authority's is how the published schema came to vouch for
# `batten.local.toml` keys the loader refuses or silently drops, so the gate owes
# the second one every property it owes the first.
@test "a drifted override schema is reported with its own pointer" {
	printf '{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"OverrideConfig","type":"object"}\n' \
		>"$ROOT/schema/batten.local.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"schema/batten.local.schema.json:0 schema-drift"* ]]
}

@test "a missing override schema is reported rather than silently skipped" {
	rm -f "$ROOT/schema/batten.local.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"schema-missing"* ]]
}

@test "both surfaces are judged in one run, not just the first to fail" {
	# Fixing the authority's copy and re-running must not be how you discover the
	# override's is stale too.
	printf '{"title":"Drifted"}\n' >"$ROOT/schema/batten.schema.json"
	printf '{"title":"AlsoDrifted"}\n' >"$ROOT/schema/batten.local.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"schema/batten.schema.json:0 schema-drift"* ]]
	[[ "$output" == *"schema/batten.local.schema.json:0 schema-drift"* ]]
}

@test "a drifted schema is reported with a pointer" {
	# The shape of real drift: a key the committed schema still describes after
	# the type behind it changed.
	printf '{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Config","type":"object"}\n' \
		>"$ROOT/schema/batten.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"schema/batten.schema.json:0 schema-drift"* ]]
}

@test "a missing schema is reported rather than silently skipped" {
	rm -f "$ROOT/schema/batten.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"schema-missing"* ]]
}

@test "output is pointer-only — no schema body echoed" {
	# rule 4: the remedy is one command, so the diff body adds nothing and would
	# put the config surface itself into the log.
	printf '{"title":"AVeryDistinctiveInventedTitle"}\n' >"$ROOT/schema/batten.schema.json"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"AVeryDistinctiveInventedTitle"* ]]
}

@test "the gate leaves the tree it judges unmodified" {
	# A gate that rewrites what it judges cannot fail twice: the second run would
	# pass, laundering the drift into a clean result.
	printf '{"title":"Drifted"}\n' >"$ROOT/schema/batten.schema.json"
	before="$(cat "$ROOT/schema/batten.schema.json")"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(cat "$ROOT/schema/batten.schema.json")" = "$before" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "this repo's committed schema matches its config types — the gate on the real tree" {
	# The self-consumption case: run against the actual repository, so the suite
	# also asserts the committed artifact is current.
	unset SCHEMA_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}
