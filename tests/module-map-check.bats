#!/usr/bin/env bats
# subject: mise-tasks/module-map-check.sh
# module-map-check's decision table (CLOUD-194): mem:core's completeness as an
# exit code. Fixtures are real git trees, since the gate walks `git ls-files`.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/module-map-check.sh"
	ROOT="$BATS_TEST_TMPDIR/repo"
	MAP="$ROOT/.serena/memories/core.md"
	mkdir -p "$ROOT/.serena/memories" "$ROOT/crates/demo/src"
	git init -q "$ROOT"
	git -C "$ROOT" config user.email t@example.com
	git -C "$ROOT" config user.name t
	export MODMAP_ROOT="$ROOT"
}

commit_all() {
	git -C "$ROOT" add -A && git -C "$ROOT" commit -qm x
}

@test "a module with a map row exits 0" {
	echo "fn main() {}" >"$ROOT/crates/demo/src/main.rs"
	printf -- '- `main.rs` — the binary boundary.\n' >"$MAP"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a module with no map row is reported with a pointer" {
	echo "pub fn f() {}" >"$ROOT/crates/demo/src/severity.rs"
	printf -- '- `main.rs` — the binary boundary.\n' >"$ROOT/.serena/memories/core.md"
	echo "fn main() {}" >"$ROOT/crates/demo/src/main.rs"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"crates/demo/src/severity.rs:0 module-map-missing-row (severity.rs)"* ]]
}

@test "output is pointer-only — no map or source prose echoed" {
	echo "pub fn secret_helper() {}" >"$ROOT/crates/demo/src/hidden.rs"
	printf -- '- `main.rs` — the binary boundary, a distinctive phrase.\n' >"$MAP"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"secret_helper"* ]]
	[[ "$output" != *"distinctive phrase"* ]]
}

@test "an untracked module is not yet the map's problem" {
	printf -- '- `main.rs` — the binary boundary.\n' >"$MAP"
	echo "fn main() {}" >"$ROOT/crates/demo/src/main.rs"
	commit_all
	# Written but never added: `git ls-files` does not see it, so neither does
	# the gate. The row is owed when the module lands, not while it is a draft.
	echo "pub fn f() {}" >"$ROOT/crates/demo/src/draft.rs"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a bare filename mention does not satisfy the row" {
	# The map names modules in backticks. A prose mention elsewhere (a sentence
	# about severity.rs, say) must not read as a row, or the gate passes on the
	# very drift it exists to catch.
	echo "pub fn f() {}" >"$ROOT/crates/demo/src/severity.rs"
	printf -- 'Note: severity.rs is described in another memory.\n' >"$MAP"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"module-map-missing-row (severity.rs)"* ]]
}

@test "a missing map is reported once, not once per module" {
	echo "fn main() {}" >"$ROOT/crates/demo/src/main.rs"
	echo "pub fn f() {}" >"$ROOT/crates/demo/src/other.rs"
	rm -f "$MAP"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"module-map-missing"* ]]
	[ "$(grep -c "module-map-missing-row" <<<"$output" || true)" -eq 0 ]
}

@test "every module of this repo has a row — the gate on the real tree" {
	# The self-consumption case: run against the actual repository, which is the
	# assertion that this change also fixed the gap it was written for.
	unset MODMAP_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}
