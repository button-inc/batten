#!/usr/bin/env bats
# memories-check's decision table (CLOUD-183, CLOUD-291): the memory graph's
# edges as exit codes. Fixtures are real git trees, since the gate walks
# `git ls-files`.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/memories-check"
	ROOT="$BATS_TEST_TMPDIR/repo"
	MEM="$ROOT/.serena/memories"
	mkdir -p "$MEM/workflow"
	git init -q "$ROOT"
	git -C "$ROOT" config user.email t@example.com
	git -C "$ROOT" config user.name t
	echo "# root" >"$MEM/core.md"
	export MEMCHECK_ROOT="$ROOT"
	index_rows core
}

commit_all() {
	git -C "$ROOT" add -A && git -C "$ROOT" commit -qm x
}

# The routing table the index conjunct joins against, in the shape the
# always-loaded surface writes it. APPENDS: a fixture that writes its own
# AGENTS.md keeps the rows, and a test can index memories as it creates them.
index_rows() {
	local name
	for name in "$@"; do
		printf '| `%s` | read it when |\n' "$name" >>"$ROOT/AGENTS.md"
	done
}

@test "a coherent graph exits 0" {
	echo 'see `mem:workflow/fanout` for the protocol' >"$MEM/topic.md"
	echo "# fanout" >"$MEM/workflow/fanout.md"
	index_rows topic workflow/fanout
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a stale reference is reported with a file:line pointer" {
	echo 'read `mem:workflow/missing` first' >"$MEM/topic.md"
	index_rows topic
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"topic.md:1 mem-ref-stale (workflow/missing)"* ]]
}

@test "references outside the memories tree are checked too" {
	echo 'protocol: `mem:nope`' >>"$ROOT/AGENTS.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"AGENTS.md:2 mem-ref-stale (nope)"* ]]
}

@test "the convention template's example references are excluded" {
	printf 'example: `mem:frontend/core` and `mem:auth/login`\n' >"$MEM/memory_maintenance.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a .md.md memory is reported as shadowed" {
	echo x >"$MEM/oops.md.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memory-name-shadowed"* ]]
}

@test "a memory name outside the reference charset is reported" {
	echo x >"$MEM/bad name.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memory-name-unreferencable"* ]]
}

@test "a missing graph root is reported" {
	rm "$MEM/core.md"
	echo x >"$MEM/other.md"
	index_rows other
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memory-root-missing"* ]]
}

# --- routing-table membership (CLOUD-291) -------------------------------------

@test "a memory with no index row is reported and names itself" {
	echo "# orphan" >"$MEM/orphan.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"orphan.md:0 memory-unindexed (orphan)"* ]]
}

@test "a fully indexed tree exits 0 and reports nothing" {
	echo "# a" >"$MEM/alpha.md"
	echo "# b" >"$MEM/workflow/beta.md"
	index_rows alpha workflow/beta
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"memory-unindexed"* ]]
}

@test "the exempt template needs no index row" {
	echo "# template" >"$MEM/memory_maintenance.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"memory-unindexed"* ]]
}

@test "a nested memory is matched in the form the index writes it" {
	echo "# fanout" >"$MEM/workflow/fanout.md"
	index_rows fanout
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memory-unindexed (workflow/fanout)"* ]]

	index_rows workflow/fanout
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a missing index is reported rather than skipped" {
	rm "$ROOT/AGENTS.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"AGENTS.md:0 memory-index-missing"* ]]
}

@test "an unindexed memory is reported as a pointer, never as content" {
	printf 'the body nobody may print\n' >"$MEM/orphan.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"the body nobody may print"* ]]
	[[ "$output" != *"read it when"* ]]
}

@test "an untracked memory is not judged" {
	commit_all
	echo "# scratch" >"$MEM/scratch.md"
	run "$CHECK"
	[ "$status" -eq 0 ]
}
