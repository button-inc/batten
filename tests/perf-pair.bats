#!/usr/bin/env bats
# subject: mise-tasks/perf-pair.sh
# Static properties of the paired driver.
#
# The measurement itself needs two release builds and a worktree, so it is not
# exercised here — `tests/perf-compare.bats` covers the decision, and this
# covers the two setup choices that are invisible until they fail in a way that
# looks like something else.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/perf-pair.sh"
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
	# Six paths, each pointing at the same materialised fixture. `wired` joins
	# them (CLOUD-697): its two arms differ in which WIRING runs, not in the
	# directory hyperfine is invoked from. `passthrough` joined with CLOUD-777,
	# `posttool` with CLOUD-919.
	#
	# The `env -C` those arms carry (CLOUD-824) is not an exception to this. It
	# sets the CHILD's cwd so each binary reads its own tree's `batten.toml` —
	# exactly what the deleted launcher's `cd` did, and what the case above
	# protects — while hyperfine itself is still invoked from the pinned fixture.
	run bash -c "grep -cE '^pair [a-z]+ .*\\\$check_repo' '$TASK'"
	[ "$output" -eq 6 ]
}

# THE GAP THIS CLOSES (CLOUD-697). `perf-assert` budgets four paths; this task
# measured three, so `perf-compare` was blind to `wired` — the entry point
# `.claude/settings.json` actually invokes, and the number an agent waits on.
# Asserted as a COUNT against the budgeted set rather than by name, so a fifth
# path added to `perf-assert` and forgotten here fails this case instead of
# shipping another silent hole.
@test "every path perf-assert budgets is paired here" {
	# Read the BUDGETS block itself rather than grepping for names: the first
	# entry shares its line with the assignment, so a name-anchored count silently
	# loses it — which this case caught on its first run.
	budgeted=$(sed -n "/^BUDGETS='/,/'$/p" "$BATS_TEST_DIRNAME/../mise-tasks/perf-assert.sh" |
		tr -d "'" | sed 's/^BUDGETS=//' | grep -cE '^[a-z]+ [0-9]+$')
	paired=$(grep -cE '^pair (noop|check|hook|wired|passthrough|posttool) ' "$TASK")
	# perf-assert budgets the gated paths only; `check` is measured and ungated,
	# so the paired set is the budgeted set plus it.
	[ "$paired" -eq $((budgeted + 1)) ]
}

# The wired arms must pin their binary rather than inherit whatever the tree has
# in `target/`. Two arms, two binaries, and neither may resolve the other's.
#
# ASSERTED OVER THE CALL SITES since CLOUD-824, because the mechanism moved. It
# used to count two literal `BATTEN_BIN=$base_bin` / `$head_bin` assignments,
# which worked while the arm was a hardcoded launcher invocation. The launcher is
# gone and each arm now derives its own tree's wiring, so the pinning happens in
# one arm-agnostic helper — and the property to hold is that the helper takes the
# binary as a PARAMETER and each call site passes its own.
@test "the wired arms pin their binary per arm, not by resolution order" {
	run bash -c "grep -cE 'wired_command \"\\\$(base_tree|PWD)\" \"\\\$(base|head)_bin\"' '$TASK'"
	[ "$output" -eq 2 ]
}

@test "the helper cannot reach an arm's binary except through its parameter" {
	# The other half, and the one that makes the case above a decision rather than
	# a spelling: a helper naming `$head_bin` directly would satisfy two call sites
	# and still measure one binary twice.
	body=$(sed -n '/^wired_command() {/,/^}/p' "$TASK")
	[ -n "$body" ]
	[[ "$body" != *'$head_bin'* ]]
	[[ "$body" != *'$base_bin'* ]]
	# And it must actually USE the parameter, in both places a binary can enter:
	# the launcher's resolution candidate, and the rewrite of a wiring that names
	# the binary rather than a path.
	[[ "$body" == *'BATTEN_BIN=%s'* ]]
	[[ "$body" == *'command="$bin '* ]]
}

@test "each wired arm runs in its OWN tree, which is what replaced the cd" {
	# `wired`'s whole distinction from `hook` is that it adjudicates against the
	# repository's real `batten.toml` rather than the pinned one-rule fixture. The
	# launcher's `cd` bought that; since CLOUD-824 `env -C` does. A head arm left
	# in the fixture repo would measure a smaller policy and read as a speedup.
	run grep -cE 'env -C %s' "$TASK"
	[ "$output" -eq 1 ]
	# Refused rather than assumed: BSD `env` has no `-C`, and measuring without it
	# would run a different experiment under this one's name.
	run grep -cE 'env -C / true' "$TASK"
	[ "$output" -eq 1 ]
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

# THE LOAD-BEARING HALF (CLOUD-697). Once `wired` is measured the object is the
# binary PLUS its wiring, so a commit touching only the launcher changes the
# measured cost. Keyed to the old set, such a commit skipped the very gate it
# needed — an arm that never runs on the commits it exists to judge.
@test "the skip also sees the wiring, not only the binary" {
	run grep -c '\.claude/hooks/' "$TASK"
	[ "$output" -gt 0 ]
	run grep -c '\.claude/settings\.json' "$TASK"
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
