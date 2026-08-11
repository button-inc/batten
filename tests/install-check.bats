#!/usr/bin/env bats
# The gate that makes CLOUD-65's three acceptance clauses computable.
#
# What it is defending is a rename. `mise-tasks/dist` decides what a release
# archive is called; `install.sh` and `[package.metadata.binstall]` each resolve
# an asset BY THAT NAME, from a machine that has never seen this repository. So
# a change to the naming rule that forgets one of the readers is green in CI,
# green in the release matrix, and a 404 on a user's machine — the one place
# nobody here is watching. Every failing case below is that shape.
#
# The fixture is a scratch repository holding COPIES of the four real files, so
# each case mutates exactly one of them and the gate judges a tree that differs
# from this one in a single, named way. Copies rather than symlinks for the same
# reason `tests/prebuilt-lint.bats` copies its gated files: a test that mutates
# a symlink mutates the repository it is run from.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/install-check"
	SRC="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT/mise-tasks" "$ROOT/crates/batten" "$ROOT/.github/workflows"
	cp "$SRC/install.sh" "$ROOT/install.sh"
	cp "$SRC/mise-tasks/dist" "$ROOT/mise-tasks/dist"
	cp "$SRC/Cargo.toml" "$ROOT/Cargo.toml"
	cp "$SRC/crates/batten/Cargo.toml" "$ROOT/crates/batten/Cargo.toml"
	WORKFLOW="$ROOT/.github/workflows/release-artifacts.yml"
	cd "$ROOT" || return 1
	git init -q .
	# `git add` alone populates the index, which is what `git ls-files` reads —
	# no commit, and therefore no identity config, is needed.
	git add -A
}

# The matrix, in the same list-item shape the real workflow uses. Defaults to
# the set install.sh serves plus the Windows leg it deliberately does not.
write_workflow() {
	if [ "$#" -eq 0 ]; then
		set -- $("$ROOT/install.sh" --targets) x86_64-pc-windows-gnu
	fi
	{
		echo "        include:"
		for t in "$@"; do
			echo "          - target: $t"
			echo "            build-tool: cargo"
		done
	} >"$WORKFLOW"
}

@test "the tree as it stands agrees across dist, install.sh and binstall" {
	write_workflow
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"name-agree across dist, install.sh and binstall"* ]]
}

@test "THE DEFECT: a matrix target install.sh does not serve fails, naming it" {
	write_workflow "$("$ROOT/install.sh" --targets | tr '\n' ' ')" riscv64gc-unknown-linux-gnu
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"riscv64gc-unknown-linux-gnu"* ]]
	[[ "$output" == *"absent from install.sh --targets"* ]]
}

@test "a target install.sh claims that no matrix leg builds fails the other way" {
	write_workflow x86_64-unknown-linux-musl x86_64-pc-windows-gnu
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"built by no matrix leg"* ]]
}

@test "THE DEFECT: renaming the archive in dist breaks the install path" {
	write_workflow
	sed -i "s/'%s-v%s-%s'/'%s_%s_%s'/" "$ROOT/mise-tasks/dist"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install.sh asks for"* ]]
}

@test "THE DEFECT: a binstall pkg-url that resolves elsewhere fails" {
	write_workflow
	sed -i 's|^pkg-url = .*|pkg-url = "{ repo }/releases/download/{ version }/{ name }{ archive-suffix }"|' \
		"$ROOT/crates/batten/Cargo.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"binstall would fetch"* ]]
}

@test "THE DEFECT: a committed executable fails, naming the path and nothing else" {
	write_workflow
	printf '\x7fELF\x02\x01\x01\x00' >"$ROOT/vendored-tool"
	git add -A
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"vendored-tool"* ]]
	[[ "$output" == *"executable binary is committed"* ]]
}

@test "a text file that happens to start MZ is not an executable" {
	write_workflow
	printf 'MZ is also how a PE header starts.\n' >"$ROOT/note.md"
	git add -A
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "an empty matrix is exit 2 — a gate that checks nothing must not report green" {
	: >"$WORKFLOW"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no matrix targets"* ]]
}

@test "a missing install.sh is exit 2, not a passing contract" {
	write_workflow
	rm "$ROOT/install.sh"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"install.sh"* ]]
}

@test "a manifest with no binstall metadata is exit 2 — that half is unimplemented" {
	write_workflow
	sed -i '/^pkg-url = /d' "$ROOT/crates/batten/Cargo.toml"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no pkg-url"* ]]
}

@test "a pkg-fmt with no suffix rule is exit 2, never a guessed extension" {
	write_workflow
	sed -i 's/^pkg-fmt = "tgz"/pkg-fmt = "txz"/' "$ROOT/crates/batten/Cargo.toml"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no suffix rule for"* ]]
}
