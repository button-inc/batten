#!/usr/bin/env bats
# CLOUD-514, phase 2. The gate that prices filing over fixing.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the record is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would read (and be judged against) the real
# session's board writes. Same reasoning as `issue-search-guard.bats`.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/filed-here-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	rm -rf "$REPO"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet --initial-branch=work
	# Per fixture, never inherited — a CI runner carries no global identity, so a
	# bare `git commit` here fails only there (CLOUD-513).
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	RECORD="$REPO/.git/batten-receipts/board-writes.work"
	mkdir -p "$REPO/.git/batten-receipts"
	cd "$REPO" || return 1
}

# The recorder's line shape, named once: kind, id, the tracker's updatedAt, the
# stored `ready-lint` verdict.
record() { printf '%s\n' "$@" >>"$RECORD"; }

@test "a create recorded with an unready verdict stops the lap, and the refusal names the id" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-unrefined"* ]]
	[[ "$output" == *"filed-here-check"* ]]
}

# THE OTHER DIRECTION (CLOUD-418): the same row, refined, passes. A suite that
# only ever asserts the refusal cannot tell a working gate from one wired shut.
@test "the same row passes once its recorded verdict is green" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

# THE LAST VERDICT PER ID WINS, which is what makes the third remedy this gate
# prints reachable at all. `board-write-record` writes a fresh line when a row
# this branch filed is groomed; reading every line instead leaves the
# creation-time `unready` standing beside the `ready` that supersedes it, which
# held PR #525 for its whole life with no remedy that could clear it.
@test "a groom recorded after the create supersedes it" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

# THE DISCRIMINATING DIRECTION: last, not "a `ready` anywhere in the file". A gate
# passing on the mere presence of one green line would let a row be groomed and
# then gutted, and could never refuse a row it had once passed.
@test "a later unready supersedes an earlier ready" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z unready"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-unrefined"* ]]
}

@test "superseding is per id: one row groomed leaves another's refusal standing" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready" \
		"issue CLOUD-901 2026-08-19T00:00:00.000Z unready" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-901 filed-unrefined"* ]]
	[[ "$output" != *"CLOUD-900 filed-unrefined"* ]]
}

# The pass line reports how many rows the branch FILED, not how many times they
# were linted — a re-lint that moved the count would make grooming look like
# filing again, which is the arithmetic this whole pair exists to hold.
@test "a re-lint of one row does not inflate the filed count" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 row(s) filed"* ]]
}

@test "a recorded comment is never gated, whatever its verdict column says" {
	record "comment CLOUD-900 2026-08-19T00:00:00.000Z -" \
		"comment CLOUD-901 2026-08-19T00:00:00.000Z unready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

# `-` is the recorder's "could not look": `ready-lint` exited 2, or could not run
# at all because a hook inherits the tool call's cwd and mise could not resolve
# the project from it. Reading that as a refusal would stop the lap over the
# environment rather than over the row.
@test "a create the recorder could not lint is not a refusal" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z -"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

@test "one unrefined row among refined ones is reported, and only that one" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready" \
		"comment CLOUD-901 2026-08-19T00:00:00.000Z -" \
		"issue CLOUD-902 2026-08-19T00:00:00.000Z unready" \
		"issue CLOUD-903 2026-08-19T00:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-902 filed-unrefined"* ]]
	[[ "$output" != *"CLOUD-900 filed-unrefined"* ]]
	[[ "$output" != *"CLOUD-903 filed-unrefined"* ]]
}

# THE PATH THE DESIGN WANTS TO BE CHEAPEST: fix it here, write nothing to the
# board. Nothing recorded, nothing to check, and the gate must be silent about it
# rather than treating an absent record as a failure to file.
@test "a branch that filed nothing passes untouched" {
	rm -f "$RECORD"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

@test "an empty record passes" {
	: >"$RECORD"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# A branch that predates the recorder can never have a record, and cannot be
# given one: the store lives under `$GIT_DIR` and is never committed.
@test "a record belonging to another branch is not read" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	git checkout -q -b other
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

@test "a branch name with a slash finds its record, matching the recorder's spelling" {
	git checkout -q -b feature/thing
	printf '%s\n' "issue CLOUD-900 2026-08-19T00:00:00.000Z unready" \
		>"$REPO/.git/batten-receipts/board-writes.feature-thing"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-unrefined"* ]]
}

@test "outside a git repository the gate fails open rather than stopping every lap" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run env GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR" "$GATE"
	[ "$status" -eq 0 ]
}

@test "a detached HEAD has no branch to key on, and fails open" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	git checkout -q --detach
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

# Pointer-only, non-negotiable 4. The recorder never wrote a title or a body, so
# there is none here to leak — this asserts the shape stays that way.
@test "the refusal carries the id and no prose from the row" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"2026-08-19T00:00:00.000Z"* ]]
}

@test "a malformed line is skipped rather than judged" {
	record "issue" "" "garbage" "issue CLOUD-900" "issue CLOUD-901 2026-08-19T00:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-unrefined"* ]]
}

@test "the bypass is honoured" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	run env BATTEN_FILED_HERE_BYPASS=1 "$GATE"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# The refusal has to be actionable without leaving the terminal: the three sinks,
# cheapest first, and the command that answers the same question locally.
@test "the refusal names the three sinks and the local check" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready"
	run "$GATE"
	[[ "$output" == *"Fix it here"* ]]
	[[ "$output" == *"comment there instead"* ]]
	[[ "$output" == *"mise run ready-lint"* ]]
}

@test "the pass line counts creates and comments separately" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready" \
		"comment CLOUD-901 2026-08-19T00:00:00.000Z -" \
		"comment CLOUD-902 2026-08-19T00:00:00.000Z -"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 row(s) filed"* ]]
	[[ "$output" == *"2 comment(s)"* ]]
}
