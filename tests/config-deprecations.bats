#!/usr/bin/env bats
# subject: mise-tasks/config-deprecations.sh
# The contract half of the config deprecation grammar (CLOUD-360): did a key
# leave the published schema without a window?
#
# Fixtures follow `schema-check.bats`' shape for the same reason — the gate runs
# `cargo run`, so a fixture needs a real workspace rather than a bare directory.
# Each is a scratch root symlinking the manifest and sources and holding its OWN
# git history, because what this gate reads is a blob at a TAG: the baseline is a
# published release, so a fixture has to be able to publish one.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/config-deprecations.sh"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp -R "$REPO/schema" "$ROOT/schema"
	export SCHEMA_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"

	# A real repository with a real tag, hermetically: the gate resolves its
	# baseline with `git tag` and reads the blob at it, so neither can be faked
	# with a plain directory.
	git -C "$ROOT" init -q
	git -C "$ROOT" config user.email t@t
	git -C "$ROOT" config user.name t
	git -C "$ROOT" add -A
	git -C "$ROOT" -c commit.gpgsign=false commit -qm "seed"
	git -C "$ROOT" tag v0.0.1
}

@test "a schema that lost no key exits 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no key left the schema unannounced"* ]]
}

# The gate's whole reason for existing. A key present at the released tag and
# absent now, with neither table naming it, is a silent break for every consumer
# still carrying it.
@test "an unannounced removal is reported rather than passed" {
	# Remove a key from the BASELINE's side by publishing a schema that declares
	# one this build does not. Equivalent to the real shape — a key that was
	# published and is now gone — and reachable without editing the config types.
	python3 - "$ROOT/schema/batten.schema.json" <<-'PY'
		import json, sys
		path = sys.argv[1]
		doc = json.load(open(path))
		doc["properties"]["a_key_that_was_published_and_is_now_gone"] = {"type": "string"}
		json.dump(doc, open(path, "w"), indent=2)
	PY
	git -C "$ROOT" add -A
	git -C "$ROOT" -c commit.gpgsign=false commit -qm "publish an extra key"
	git -C "$ROOT" tag v0.0.2
	# Put the working tree's schema back to what the types actually derive, so the
	# key exists only at the tag — which is exactly "it was released and then
	# removed".
	cp "$REPO/schema/batten.schema.json" "$ROOT/schema/batten.schema.json"

	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"a_key_that_was_published_and_is_now_gone"* ]]
	[[ "$output" == *"no deprecation window"* ]]
}

# COULD NOT LOOK is exit 3, never 0. Reporting "nothing was removed" having
# compared nothing is the vacuous pass CLOUD-251 names, and it is the one answer
# this gate must never give.
@test "no release tag is exit 3 rather than a clean pass" {
	git -C "$ROOT" tag -d v0.0.1
	run "$CHECK"
	[ "$status" -eq 3 ]
	[[ "$output" == *"no release tag"* ]]
}

@test "a tag carrying no published schema is exit 3 rather than a clean pass" {
	git -C "$ROOT" rm -q --cached schema/batten.schema.json
	rm -f "$ROOT/schema/batten.schema.json"
	git -C "$ROOT" -c commit.gpgsign=false commit -qm "no schema here"
	git -C "$ROOT" tag v0.0.3
	# Restore the working tree's copy: the baseline is what lacks it.
	cp "$REPO/schema/batten.schema.json" "$ROOT/schema/batten.schema.json"
	run "$CHECK"
	[ "$status" -eq 3 ]
	[[ "$output" == *"no published schema"* ]]
}

@test "the baseline is the newest tag by version order, not by creation time" {
	# A re-cut or back-dated tag must not reorder the baseline: v0.0.10 is newer
	# than v0.0.9 even when created first.
	git -C "$ROOT" tag v0.0.10
	git -C "$ROOT" tag v0.0.9
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"v0.0.10"* ]]
}

@test "output is pointer-only — no schema body echoed" {
	# rule 4: the remedy is declaring a window, so the schema body adds nothing
	# and would put the config surface into the log.
	python3 - "$ROOT/schema/batten.schema.json" <<-'PY'
		import json, sys
		path = sys.argv[1]
		doc = json.load(open(path))
		doc["properties"]["gone_key"] = {"description": "AVeryDistinctiveInventedSentence"}
		json.dump(doc, open(path, "w"), indent=2)
	PY
	git -C "$ROOT" add -A
	git -C "$ROOT" -c commit.gpgsign=false commit -qm "publish"
	git -C "$ROOT" tag v0.0.4
	cp "$REPO/schema/batten.schema.json" "$ROOT/schema/batten.schema.json"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"gone_key"* ]]
	[[ "$output" != *"AVeryDistinctiveInventedSentence"* ]]
}

@test "the gate leaves the tree it judges unmodified" {
	# A gate that rewrites what it judges cannot fail twice.
	before="$(cat "$ROOT/schema/batten.schema.json")"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ "$(cat "$ROOT/schema/batten.schema.json")" = "$before" ]
}

@test "this repo's own schema has lost no key since its last release — the gate on the real tree" {
	# The self-consumption case, and the one the replay evidence generalises:
	# across all 112 tags this predicate reported zero violations.
	unset SCHEMA_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}
