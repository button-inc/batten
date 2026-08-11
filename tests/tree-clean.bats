#!/usr/bin/env bats
# The precondition under `verify`'s receipt: a receipt keyed to HEAD may only be
# written when the bytes validated WERE the bytes at HEAD (CLOUD-277).
#
# Behavioural, in throwaway repositories, because the property is about git state
# and a textual assertion over the gate would only restate its source. The
# load-bearing case is the LAST one: a dirty tree whose contents would pass still
# leaves HEAD unverified. The measured incident failed loudly (a mid-edit
# snapshot that would not compile); the one this gate exists for passes quietly.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/tree-clean"
	VERIFIED="$BATS_TEST_DIRNAME/../mise-tasks/verified"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	git init -q "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	printf 'fn main() {}\n' >src.rs
	printf '/scratch\n' >.gitignore
	git add src.rs .gitignore
	git commit -q -m "chore: init"
	HEAD_SHA=$(git rev-parse HEAD)
	# The gate resolves its root from git unless told otherwise; naming it keeps
	# every case scoped to its own throwaway repo rather than to this one.
	TREE_CLEAN_ROOT="$REPO"
	export TREE_CLEAN_ROOT
}

@test "a clean tree passes and names the commit the receipt would be about" {
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"matches HEAD ${HEAD_SHA:0:8}"* ]]
}

@test "a modified tracked file exits 1 and names the path" {
	printf 'fn main() { todo!() }\n' >src.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"src.rs"* ]]
	[[ "$output" == *"1 path(s)"* ]]
}

@test "staged but uncommitted is dirty — the index is not HEAD" {
	printf 'fn main() { todo!() }\n' >src.rs
	git add src.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"src.rs"* ]]
}

@test "AN UNTRACKED FILE IS DIRTY — decided, not omitted" {
	# `git diff --quiet HEAD --` cannot see this, and the gap is not theoretical:
	# `cargo test` auto-discovers crates/batten/tests/*.rs and the bats suite
	# globs tests/*.bats, so a new untracked file is compiled and run by `verify`
	# with zero tracked-file change. A receipt after that attests bytes no commit
	# contains. Asserted here so the decision cannot decay back into an omission.
	printf '@test "new" { true; }\n' >new_test.bats
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"new_test.bats"* ]]
}

@test "an ignored file is not dirty — scratch is excluded structurally" {
	mkdir -p scratch
	printf 'notes\n' >scratch/notes.md
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a deleted tracked file is dirty" {
	rm src.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"src.rs"* ]]
}

@test "the count is the number of paths, not a fixed string" {
	printf 'fn main() { todo!() }\n' >src.rs
	printf 'x\n' >other.txt
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"2 path(s)"* ]]
}

@test "output is a pointer — paths and a count, never the differing content" {
	printf 'SECRET_SENTINEL_VALUE\n' >src.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"SECRET_SENTINEL_VALUE"* ]]
}

@test "the refusal names the fix, not merely the refusal" {
	printf 'fn main() { todo!() }\n' >src.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ommit"* ]]
	[[ "$output" == *"worktree"* ]]
}

@test "outside a git repository it exits 2 — could not look is not a verdict" {
	mkdir -p "$BATS_TEST_TMPDIR/bare-$BATS_TEST_NUMBER"
	cd "$BATS_TEST_TMPDIR/bare-$BATS_TEST_NUMBER" || return 1
	TREE_CLEAN_ROOT=""
	run env TREE_CLEAN_ROOT= "$GATE"
	[ "$status" -eq 2 ]
}

@test "a repository with no commit exits 2 — no HEAD for a receipt to name" {
	local empty="$BATS_TEST_TMPDIR/empty-$BATS_TEST_NUMBER"
	git init -q "$empty"
	run env TREE_CLEAN_ROOT="$empty" "$GATE"
	[ "$status" -eq 2 ]
}

@test "THE ACCEPTANCE CASE: a dirty tree that would PASS still leaves HEAD unverified" {
	# `verify`'s body shape, with the gate standing where it stands there and the
	# steps after it stubbed green — so the only reason the receipt is missing is
	# the dirty tree, not a failure of the thing being verified.
	git update-ref refs/remotes/origin/main HEAD
	local receipts
	receipts="$(git rev-parse --git-dir)/batten-receipts"
	mkdir -p "$receipts"
	printf 'fn main() { /* compiles fine */ }\n' >src.rs

	run bash -c '
		if ! "$1"; then echo "::error:: no receipt written" >&2; exit 1; fi
		date -u +%FT%TZ >"$2/verify.$3"
		printf "%s" "$(git rev-parse origin/main)" >"$2/linear-check.$3"
	' _ "$GATE" "$receipts" "$HEAD_SHA"
	[ "$status" -eq 1 ]
	[ ! -f "$receipts/verify.$HEAD_SHA" ]

	# And that absence is what the next gate in the chain reads.
	run "$VERIFIED"
	[ "$status" -eq 1 ]
	[[ "$output" == *"NOT verified"* ]]
}
