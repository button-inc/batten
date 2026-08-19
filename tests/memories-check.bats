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
}

commit_all() {
	git -C "$ROOT" add -A && git -C "$ROOT" commit -qm x
}

@test "a coherent graph exits 0" {
	echo 'see `mem:workflow/fanout` for the protocol' >"$MEM/topic.md"
	echo "# fanout" >"$MEM/workflow/fanout.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a stale reference is reported with a file:line pointer" {
	echo 'read `mem:workflow/missing` first' >"$MEM/topic.md"
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
	[[ "$output" == *"AGENTS.md:1 mem-ref-stale (nope)"* ]]
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
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memory-root-missing"* ]]
}

# --- routing-table membership (CLOUD-291) -------------------------------------

@test "an untracked memory is not judged" {
	commit_all
	echo "# scratch" >"$MEM/scratch.md"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

# --- membership is not a property this gate asserts (CLOUD-683) --------------
#
# Serena surfaces every memory name to the agent each session, so an unreferenced
# memory is discoverable and is not a defect. Only a DANGLING reference is. These
# cases pin that contract so it cannot be quietly re-tightened.

@test "a memory with neither an index row nor a reference passes" {
	echo "# standalone" >"$MEM/standalone.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "no index file is needed at all" {
	rm -f "$ROOT/AGENTS.md"
	echo "# standalone" >"$MEM/standalone.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a dangling reference is still the failure, pointer-only" {
	printf 'the body nobody may print\nsee `mem:gone`\n' >"$MEM/topic.md"
	commit_all
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"topic.md:2 mem-ref-stale (gone)"* ]]
	[[ "$output" != *"the body nobody may print"* ]]
}
