#!/usr/bin/env bats
# Static properties of the paired driver.
#
# The measurement itself needs two release builds and a worktree, so it is not
# exercised here — `tests/perf-compare.bats` covers the decision, and this
# covers the two setup choices that are invisible until they fail in a way that
# looks like something else.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/perf-pair"
}

# THE MEASURED DEFECT (CLOUD-172). Both arms used to run in the repo root, so
# the BASE binary — built from the merge base — was handed HEAD's committed
# `batten.toml`. A head that adds a config key the base binary does not know
# makes that binary exit 1 at load, hyperfine abort on its first warmup, and the
# gate answer 2. Measured: a `[worktree]` key on the head produced
# "unknown field `worktree`" from the base arm and took the whole gate down —
# a could-not-look manufactured by the gate's own setup, on exactly the class of
# change it exists to judge.
#
# The fix is that every arm runs in the materialised fixture, whose config is
# pinned and loadable by both binaries. This asserts the fix as a property,
# because the failure needs two real binaries an hour apart to reproduce.
@test "no arm is measured in the checkout — a stale binary must not read HEAD's config" {
	run grep -nE '^pair [a-z]+ "\$PWD"' "$TASK"
	[ "$status" -ne 0 ]
}

@test "every arm is measured in the pinned fixture repo" {
	# Three paths, each pointing at the same materialised fixture.
	run bash -c "grep -cE '^pair [a-z]+ \"\\\$check_repo\"' '$TASK'"
	[ "$output" -eq 3 ]
}

# hyperfine aborts on a non-zero exit unless `-i` is passed, and that is
# deliberate: every path exits 0 on its fixture, so ignoring failures would buy
# nothing and would publish a binary that had started failing outright as a fast
# number rather than a broken one.
@test "failures are not ignored — a broken binary is timeable and must not pass" {
	run grep -nE 'hyperfine .*-i ' "$TASK"
	[ "$status" -ne 0 ]
}

# The skip is what keeps `verify` cheap, and it is sound only while it is keyed
# to what can actually change the binary.
@test "the skip is keyed to the paths that can change the binary" {
	run grep -c 'crates/\|Cargo\.lock\|Cargo\.toml' "$TASK"
	[ "$output" -gt 0 ]
}

# A killed run never reaches the EXIT trap that removes the worktree, and `land`
# kills this gate on purpose whenever `main-watch` wins the race. What survives is
# the ADMIN ENTRY under `.git/worktrees` with its directory already gone — after
# which `git worktree add` refuses that path forever and every later `verify` in
# the clone fails at "could not create a worktree", having measured nothing.
#
# Measured 2026-08-14, on the landing immediately after this gate went in.
@test "a leaked worktree entry cannot wedge the next run: prune precedes add" {
	local prune add
	# Executable lines only — the comment above the fix names `git worktree add`
	# to explain what it prevents, and matching that would compare prose.
	prune=$(grep -nE '^\s*git worktree prune' "$TASK" | head -n1 | cut -d: -f1)
	add=$(grep -nE '^\s*if ! git worktree add' "$TASK" | head -n1 | cut -d: -f1)
	[ -n "$prune" ]
	[ -n "$add" ]
	[ "$prune" -lt "$add" ]
}

# `prune` removes only entries whose directory has already vanished, so it is safe
# beside a concurrent healthy worktree — but `remove` would not be, and reaching
# for it here is the plausible wrong fix.
@test "the recovery prunes rather than removing, so a live worktree is untouched" {
	run grep -nE '^\s*git worktree remove' "$TASK"
	[ "$status" -ne 0 ]
}
