#!/usr/bin/env bats
# config-lint's decision table (CLOUD-87): does this repository's batten.toml
# carry a policy smell?
#
# The gate runs `cargo run`, so a fixture cannot be a bare directory — it needs a
# real workspace. Each fixture is a scratch root that symlinks the manifest and
# sources of the real repo and holds its *own* batten.toml, which is the only
# thing a test mutates. CARGO_TARGET_DIR points back at the real target dir so
# the fixture compiles nothing the suite has not already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/config-lint"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp "$REPO/batten.toml" "$ROOT/batten.toml"
	# COPIED, not symlinked: the copied batten.toml declares
	# `[budget.instructions]` over AGENTS.md, and since CLOUD-50 `batten check`
	# enforces every declared budget — an entry matching no file is exit 1 per
	# entry (CLOUD-298). The tree walk counts regular files only, so a symlink
	# here would be invisible to it and the entry would read as dead.
	cp "$REPO/AGENTS.md" "$ROOT/AGENTS.md"
	export CONFIG_LINT_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "a clean config exits 0 and states its count" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 smell(s)"* ]]
}

@test "an empty protected set fails the gate with a pointer" {
	printf 'version = 1\nprotected = []\n' >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.toml:2 empty-protected-set"* ]]
}

@test "a rule switched off fails the gate" {
	{
		printf 'version = 1\n\n[[rule]]\nid = "r"\nkind = "forbid"\n'
		printf 'glob = "**/*.rs"\npattern = "x"\nseverity = "allow"\n'
	} >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rule-disabled"* ]]
}

@test "output is pointer-only — no config body echoed" {
	printf 'version = 1\n# a very distinctive comment\nprotected = []\n' >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"very distinctive comment"* ]]
}

@test "a malformed config fails the gate rather than passing it" {
	# The gate must not read "cannot parse" as "nothing to report": the binary
	# exits 1 there, and the gate has to stay non-zero either way.
	printf 'version = 1\nthis is not toml\n' >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "the gate leaves the config it judges unmodified" {
	printf 'version = 1\nprotected = []\n' >"$ROOT/batten.toml"
	before="$(cat "$ROOT/batten.toml")"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(cat "$ROOT/batten.toml")" = "$before" ]
}

@test "this repo's own config is clean — the gate on the real tree" {
	unset CONFIG_LINT_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "the rationale claims no caller that grep cannot find" {
	# CLOUD-236 / CLOUD-198. The header used to assert "CI passes
	# `--config-from origin/main`" as fact while no caller passed it, which is the
	# worst place to put a false claim: it told a reader the base-ref class was
	# covered. Truth-reconciliation only sticks if it is a gate, so this is the
	# gate — if a future edit re-asserts a caller, it must also create one.
	if grep -qE '(CI|ci) passes .*--config-from' "$CHECK"; then
		run grep -rqE -- '--config-from' "$REPO/.github" "$REPO/mise.toml" "$REPO/hk.pkl"
		[ "$status" -eq 0 ] || {
			echo "the rationale claims a --config-from caller; none exists" >&2
			false
		}
	fi
}
