#!/usr/bin/env bats
# subject: mise-tasks/target-prune.sh
# CLOUD-766. `target/deps` retained a full artifact set per build hash and
# nothing reclaimed it, so a session that lands more than a couple of issues runs
# out of disk — measured twice in one session, at ~1.5-2 GB per `land` lap.
#
# Two properties, and they fail differently. The PRUNE must remove only what a
# build will not read again: taking a cache instead forces a rebuild, which is
# how the two hand-remedies that preceded this task re-consumed the space they
# freed. The FLOOR must refuse before anything is spent, because exhaustion
# otherwise surfaces as a rustc IO error inside a test run and reads as a suite
# regression.
#
# Every case builds its own tree. Nothing here touches the repository's real
# `target/`, which would make the suite's verdict depend on how recently someone
# ran a build.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/target-prune.sh"
	ROOT="$BATS_TEST_TMPDIR/target"
	mkdir -p "$ROOT/debug/deps"
	# CLOUD-778: free space is an INPUT, so the fixture sets it. Without this the
	# header's promise that "nothing here touches the repository's real target/"
	# is false for every case that asserts a successful run — the floor is read
	# off the host, so those cases answer "how full is this disk" rather than the
	# question they ask. Measured twice: one case flipped verdict across two
	# readings minutes apart with no fixture change, and raising the floor to its
	# re-measured value turned NINE cases red in CI at once.
	#
	# Comfortably above any floor a case does not deliberately raise, so the
	# default is "the disk is not the subject". A case about the floor overrides
	# this, or raises the floor past it through the budget line.
	export TARGET_PRUNE_FREE_MB=999999
}

# An executable artifact with cargo's hash suffix, and a mtime the case controls.
# Size is what the report sums, so it is explicit rather than incidental.
artifact() { # artifact <stem> <hash> <mtime YYYYMMDDhhmm> [kb]
	local path="$ROOT/debug/deps/$1-$2"
	head -c "$((${4:-16} * 1024))" /dev/zero >"$path"
	chmod +x "$path"
	touch -t "$3" "$path"
}

surviving() { # surviving <stem>
	find "$ROOT/debug/deps" -maxdepth 1 -type f -perm -u+x -name "$1-*" | wc -l | tr -d ' '
}

@test "the newest K copies survive and the rest are removed" {
	artifact cli aaaaaaaaaaaa 202608200900
	artifact cli bbbbbbbbbbbb 202608201000
	artifact cli cccccccccccc 202608201100
	artifact cli dddddddddddd 202608201200
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ "$(surviving cli)" -eq 2 ]
	# The two KEPT are the newest, not an arbitrary two.
	[ -f "$ROOT/debug/deps/cli-cccccccccccc" ]
	[ -f "$ROOT/debug/deps/cli-dddddddddddd" ]
	[ ! -f "$ROOT/debug/deps/cli-aaaaaaaaaaaa" ]
}

@test "THE SPARE IS KEPT, so a reverted lap is not a full rebuild" {
	# K=2 rather than 1 is a hedge with a stated cost: the second-newest is what a
	# rebase that reverts would otherwise rebuild from scratch. A prune that keeps
	# only the current build reads as working and silently makes every undo
	# expensive.
	artifact cli aaaaaaaaaaaa 202608200900
	artifact cli bbbbbbbbbbbb 202608201000
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ "$(surviving cli)" -eq 2 ]
}

@test "a stem with fewer than K copies is untouched" {
	artifact solo aaaaaaaaaaaa 202608200900
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ -f "$ROOT/debug/deps/solo-aaaaaaaaaaaa" ]
	[[ "$output" == *"0 superseded"* ]]
}

@test "stems are grouped separately — one binary's copies never count as another's" {
	artifact cli aaaaaaaaaaaa 202608200900
	artifact cli bbbbbbbbbbbb 202608201000
	artifact cli cccccccccccc 202608201100
	artifact walker dddddddddddd 202608200900
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ "$(surviving cli)" -eq 2 ]
	# `walker` has one copy and keeps it, rather than being pruned because the
	# tree as a whole had four artifacts.
	[ "$(surviving walker)" -eq 1 ]
}

@test "NOTHING OUTSIDE deps IS CONSIDERED — a cache is not a superseded artifact" {
	# The distinction this whole task exists for. `incremental` and the
	# cross-target dirs regrow, so deleting them costs a rebuild; that is what
	# made two hand-remedies re-consume the space they freed.
	mkdir -p "$ROOT/debug/incremental" "$ROOT/aarch64-apple-darwin/debug"
	head -c 65536 /dev/zero >"$ROOT/debug/incremental/blob"
	head -c 65536 /dev/zero >"$ROOT/aarch64-apple-darwin/debug/blob"
	head -c 65536 /dev/zero >"$ROOT/debug/batten"
	chmod +x "$ROOT/debug/batten"
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ -f "$ROOT/debug/incremental/blob" ]
	[ -f "$ROOT/aarch64-apple-darwin/debug/blob" ]
	[ -f "$ROOT/debug/batten" ]
}

@test "a cross-target deps directory is pruned too, on the same rule" {
	mkdir -p "$ROOT/aarch64-apple-darwin/debug/deps"
	local d="$ROOT/aarch64-apple-darwin/debug/deps"
	for h in aaaaaaaaaaaa bbbbbbbbbbbb cccccccccccc; do
		head -c 16384 /dev/zero >"$d/cli-$h"
		chmod +x "$d/cli-$h"
	done
	touch -t 202608200900 "$d/cli-aaaaaaaaaaaa"
	touch -t 202608201000 "$d/cli-bbbbbbbbbbbb"
	touch -t 202608201100 "$d/cli-cccccccccccc"
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ "$(find "$d" -maxdepth 1 -type f -perm -u+x | wc -l | tr -d ' ')" -eq 2 ]
}

@test "a non-executable file beside the artifacts is left alone" {
	# `.d` depfiles and `.rlib`s are small, and a dangling one only makes cargo
	# rebuild. Removing them buys nothing and risks confusing a live build.
	artifact cli aaaaaaaaaaaa 202608200900
	artifact cli bbbbbbbbbbbb 202608201000
	artifact cli cccccccccccc 202608201100
	printf 'dep\n' >"$ROOT/debug/deps/cli-aaaaaaaaaaaa.d"
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[ -f "$ROOT/debug/deps/cli-aaaaaaaaaaaa.d" ]
}

# --- output contract ---------------------------------------------------------

@test "the report is a count and bytes, never a path listing" {
	# Pointer-only per non-negotiable rule 4. A path list is unbounded, and a
	# caller who wants one can run `du`.
	artifact SENTINEL_STEM aaaaaaaaaaaa 202608200900
	artifact SENTINEL_STEM bbbbbbbbbbbb 202608201000
	artifact SENTINEL_STEM cccccccccccc 202608201100
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[[ "$output" != *"SENTINEL_STEM-aaaaaaaaaaaa"* ]]
	[[ "$output" == *"superseded artifact(s) removed"* ]]
	[[ "$output" == *"MB free"* ]]
}

@test "the report names the floor beside the free space, so both numbers travel" {
	# DERIVED, not hardcoded (CLOUD-861). This read `floor 4096MB`, so
	# re-measuring the budget — which the row above exists to force — broke a
	# case about REPORTING rather than about the value. The property is that the
	# enforced floor reaches the reader; which number that is belongs to the
	# budget-basis case, which pins it deliberately.
	local floor
	floor=$(grep -m1 -oE '^FLOOR_MB=[0-9]+' "$TASK" | cut -d= -f2)
	[ -n "$floor" ]
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"floor ${floor}MB"* ]]
}

# --- could not look ----------------------------------------------------------

@test "an absent build directory is exit 2, never a silent pass" {
	# A caller in the wrong directory must not read as a clean tree.
	run "$TASK" --root "$BATS_TEST_TMPDIR/nowhere"
	[ "$status" -eq 2 ]
	[[ "$output" == *"nothing was examined"* ]]
}

@test "--root with no value is refused, and does not hang" {
	run timeout 10s "$TASK" --root
	[ "$status" -eq 2 ]
	[[ "$output" == *"needs a directory"* ]]
}

@test "an unknown flag is a usage error" {
	run timeout 10s "$TASK" --nonsense
	[ "$status" -eq 2 ]
}

# --- the floor carries its own arithmetic ------------------------------------
#
# `timeout-check`'s `budget-arithmetic` class, for the one budget its glob does
# not cover — the same shape `mcp-timeout-budget` took for the MCP startup
# budget.

budget_file() { # budget_file <FLOOR_MB line>
	local f="$BATS_TEST_TMPDIR/budget.sh"
	printf '%s\n' "$1" >"$f"
	printf '%s' "$f"
}

@test "a floor matching its declared basis passes" {
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=4096 # budget: worst-lap=2048mb x2 measured=2026-08-20')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
}

@test "a floor disagreeing with its declared basis is refused, and both numbers are named" {
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=4096 # budget: worst-lap=999mb x2 measured=2026-08-20')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"disagrees with the basis"* ]]
	[[ "$output" == *"1998"* ]]
}

@test "a floor with no budget comment is refused — a limit with no measurement" {
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=4096')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no parsable budget comment"* ]]
}

@test "a budget comment with no measurement date is refused" {
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=4096 # budget: worst-lap=2048mb x2')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no parsable budget comment"* ]]
}

@test "an unreadable budget file is exit 2, never a silent pass" {
	TARGET_PRUNE_BUDGET="$BATS_TEST_TMPDIR/absent-budget.sh" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 2 ]
}

# --- the floor refuses AFTER pruning -----------------------------------------

@test "THE ORDER IS LOAD-BEARING: a prunable tree is never refused for being over budget" {
	# A tree above the floor but full of superseded copies is this task's
	# ordinary case, not a stop. Checking the floor first would turn every few
	# laps into a refusal for a condition the next four lines fix.
	#
	# Asserted structurally, because a case cannot fill a real volume: the free
	# space read and the floor comparison both come after the prune loop.
	local prune_line floor_line
	prune_line=$(grep -n 'superseded artifact(s) removed' "$TASK" | head -1 | cut -d: -f1)
	floor_line=$(grep -n 'below the measured disk floor' "$TASK" | head -1 | cut -d: -f1)
	[ -n "$prune_line" ]
	[ -n "$floor_line" ]
	[ "$prune_line" -lt "$floor_line" ]
}

@test "a tree still below the floor after pruning is refused" {
	# The floor is read from the budget line, so a fixture can raise it above any
	# real volume's free space and exercise the refusal without filling a disk.
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=199999998 # budget: worst-lap=99999999mb x2 measured=2026-08-20')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"below the measured disk floor"* ]]
	[[ "$output" == *"free "* ]]
	[[ "$output" == *"floor "* ]]
}

@test "the refusal explains how exhaustion would otherwise present" {
	# The whole point of the second half: without this, the next thing the author
	# sees is a rustc IO error inside a test run, under a `land` line telling them
	# to fix their own diff.
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=199999998 # budget: worst-lap=99999999mb x2 measured=2026-08-20')" \
		run "$TASK" --root "$ROOT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"reads as a suite regression"* ]]
}

# --- CLOUD-861: the reclaim could not reach the largest thing on the disk ----
#
# The superseded pass above is the whole reclaim, and incremental state is not
# superseded by anything — it is unbounded. Measured three times in one session:
# the pass reclaimed 0MB while `target/debug/incremental` held 3.8G, the lap
# exhausted the volume, and a human deleted that directory by hand each time.
#
# The floor is read from the budget line, so these raise it above any real
# volume's free space and exercise the escalation without filling a disk — the
# same lever `a tree still below the floor after pruning is refused` uses.
incremental_cache() {
	mkdir -p "$ROOT/debug/incremental/batten-1a2b3c/s-abc-def"
	# Big enough that `du -sk` reports non-zero, which is what gates the report.
	head -c 200000 /dev/zero >"$ROOT/debug/incremental/batten-1a2b3c/s-abc-def/dep-graph.bin"
}

@test "CLOUD-861: a tree below the floor escalates and drops the incremental cache" {
	# THE DISCRIMINATING ROW. Red before the escalation: the run refused with the
	# cache untouched, which is exactly the state a human then cleared by hand.
	incremental_cache
	TARGET_PRUNE_BUDGET="$(budget_file 'FLOOR_MB=199999998 # budget: worst-lap=199999998mb x1 measured=2026-08-22')" \
		run "$TASK" --root "$ROOT"
	[[ "$output" == *"escalated below the floor"* ]]
	[[ "$output" == *"incremental cache dropped"* ]]
	[ ! -d "$ROOT/debug/incremental" ]
}

@test "CLOUD-861: a tree ABOVE the floor keeps its incremental cache" {
	# ANTI-VACUITY, and the reason the escalation is conditional. Dropping the
	# cache costs a full rebuild, so paying it every lap would trade a rare stall
	# for a permanent tax. A fix that always deleted it would pass the row above
	# and be worse than the defect.
	incremental_cache
	run "$TASK" --root "$ROOT"
	[ "$status" -eq 0 ]
	[[ "$output" != *"escalated"* ]]
	[ -d "$ROOT/debug/incremental" ]
}

@test "CLOUD-861: the floor's basis names a lap no observed lap exceeds" {
	# The budget comment is parsed, not merely readable, so a stale measurement
	# inside it reads exactly like a fresh one. 2048mb was falsified by a 6242mb
	# lap the next day; this pins the corrected figure so the next drift is a
	# failing case rather than another exhausted container.
	run grep -m1 -E '^FLOOR_MB=' "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"worst-lap=6242mb"* ]]
	[[ "$output" != *"worst-lap=2048mb"* ]]
}

# --- CLOUD-778: the suite's hermeticity claim, made true ----------------------

@test "CLOUD-778: the prune verdict is identical above and below the floor" {
	# THE ROW THAT PINS THE ISOLATION. The header promises "nothing here touches
	# the repository's real target/", and until the free-space seam that was
	# false for every case asserting a successful run: the floor was read off the
	# host, so the answer depended on how full someone's disk happened to be.
	#
	# WHICH ARTIFACTS SURVIVE is the prune's actual question, and it must not
	# move with free space. The EXIT CODE legitimately does — a tree below the
	# floor is refused, and that is the floor working — so this asserts the
	# reclaim, not the status.
	artifact batten aaaaaaaa 202601010900
	artifact batten bbbbbbbb 202601010901
	artifact batten cccccccc 202601010902

	TARGET_PRUNE_FREE_MB=999999 run "$TASK" --root "$ROOT"
	local rich_survivors
	rich_survivors=$(surviving batten)

	# Rebuild the same tree and prune it again on a disk that is nearly full.
	rm -rf "$ROOT" && mkdir -p "$ROOT/debug/deps"
	artifact batten aaaaaaaa 202601010900
	artifact batten bbbbbbbb 202601010901
	artifact batten cccccccc 202601010902

	TARGET_PRUNE_FREE_MB=1 run "$TASK" --root "$ROOT"
	[ "$(surviving batten)" -eq "$rich_survivors" ]
	# And the refusal still fires, so the seam did not delete the behaviour it
	# makes testable — the anti-vacuity half of this row.
	[ "$status" -eq 1 ]
	[[ "$output" == *"below the measured disk floor"* ]]
}
