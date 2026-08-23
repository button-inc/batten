#!/usr/bin/env bats
# subject: mise-tasks/filed-here-check.sh
# CLOUD-514, phase 2. The gate that prices filing over fixing.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the record is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would read (and be judged against) the real
# session's board writes. Same reasoning as `issue-search-guard.bats`.

setup() {
	# The caller's ambient environment must not reach a fixture, exactly as the
	# git identity below must not. Both bypasses are set per-case with `env` where
	# a case wants them; inherited, they silence the cases that assert the gate
	# FIRES — and the whole suite passes while proving nothing (CLOUD-418).
	#
	# Not hypothetical: `BATTEN_FILED_HERE_OVERLAP=1 mise run land` is remedy 4 in
	# this gate's own deny text, and it exports the variable into `verify`, which
	# runs this suite. So the documented escape hatch reddened the suite that
	# documents it, and the gate could not be overridden by the route it names.
	unset BATTEN_FILED_HERE_OVERLAP BATTEN_FILED_HERE_BYPASS
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/filed-here-check.sh"
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

# `changes <path>...` — give the fixture a real `origin/main` and a real diff
# containing those paths (CLOUD-774). The gate no longer trusts the count the
# recorder froze; it intersects the recorded paths with
# `git diff --name-only origin/main...HEAD` when it is asked. So a case about the
# diff refusal has to CREATE the diff, which is what makes these assertions about
# the predicate rather than about a number in a file.
changes() {
	git -C "$REPO" update-ref refs/remotes/origin/main HEAD
	for path in "$@"; do
		mkdir -p "$REPO/$(dirname "$path")"
		printf 'x\n' >"$REPO/$path"
	done
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m change
}

# The recorder's line shape, named once: kind, id, the tracker's updatedAt, the
# stored `ready-lint` verdict.
record() { printf '%s\n' "$@" >>"$RECORD"; }

@test "an AMBIENT bypass does not silence the gate — setup owns the environment" {
	# The suite self-test for its own setup. Both bypasses are exported here as a
	# caller would have them; `setup` cleared them, so the gate must still refuse.
	# Without this, a future setup that stops unsetting them turns every
	# fires-correctly case green for the wrong reason and nothing notices.
	# Asserted as setup's CONTRACT — the variables are absent by the time a body
	# runs — rather than by exporting them here, which would only re-prove that
	# the gate honours a bypass it can see.
	[ -z "${BATTEN_FILED_HERE_OVERLAP:-}" ]
	[ -z "${BATTEN_FILED_HERE_BYPASS:-}" ]
	printf 'issue CLOUD-1 2026-01-01T00:00:00.000Z unready 0\n' >"$RECORD"
	run "$GATE"
	[ "$status" -ne 0 ]
	[[ "$output" == *"CLOUD-1"* ]]
}

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

# --- the diff refusal (CLOUD-514, phase 3) -------------------------------------
#
# `filed-unrefined` prices REFINEMENT and its bound was stated honestly from the
# day it shipped — "it does not compare the row to the diff". That bound was the
# whole gap: a Ready block is prose, and prose is the currency an agent has
# without limit. Measured 2026-08-20, four rows filed in three and a half minutes
# and every one recorded `ready`.
#
# The fifth column is the recorder's `board-diff-overlap` reading, `<count>` then
# the tracked paths the row names, COMMA-JOINED since CLOUD-923 so one column is
# one whitespace-free token. The recorder gained a sixth column then, and a record
# whose fifth field can swallow the rest of the line cannot have a sixth.

@test "a row naming a file this branch is changing stops the lap" {
	changes crates/batten/src/git.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,crates/batten/src/git.rs"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff crates/batten/src/git.rs"* ]]
}

# THE OTHER DIRECTION (CLOUD-418). A refusal over every filed row is not a gate,
# it is an outage, and this is the reading that separates the two.
@test "a row naming only untouched files passes" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 0"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# THREE STATES HERE TOO. `-` is the recorder saying it could not look — no
# `origin/main`, outside a checkout, a body the tracker did not return — and
# reading it as a refusal turns a verdict about the environment into one about
# the row.
@test "a row the recorder could not measure passes" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready -"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# A RECORD WRITTEN BEFORE THIS COLUMN EXISTED HAS FOUR FIELDS. A branch cannot be
# refused for a question its recorder was never able to ask, and the store lives
# under `$GIT_DIR` where it cannot be migrated.
@test "a four-field line predating the column is not refused" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

@test "every overlapping path is named, one pointer per line" {
	changes a/one.rs b/two.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 2,a/one.rs,b/two.rs"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff a/one.rs"* ]]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff b/two.rs"* ]]
}

# The two refusals are different facts about the same row and neither subsumes
# the other, so a row can earn both and must report both.
@test "a row that is both unrefined and over the diff reports both" {
	changes a/one.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready 1,a/one.rs"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-unrefined"* ]]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff a/one.rs"* ]]
}

# LAST LINE WINS HERE TOO. The recorder writes a fresh line when a row this
# branch filed is groomed, and a row rewritten to be about work elsewhere is the
# second of the four remedies.
@test "a later reading with no overlap supersedes an earlier one" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z ready 0"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

@test "and a later reading WITH an overlap supersedes a clean one" {
	changes a/one.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 0" \
		"issue CLOUD-900 2026-08-19T01:00:00.000Z ready 1,a/one.rs"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"filed-over-own-diff a/one.rs"* ]]
}

# COMMENTS STAY UNGATED on this axis too. A comment on the row that already owns
# the finding is sink 2 and the honest common case; pricing it pushes the
# pressure toward silence.
@test "a comment is never gated on the diff either" {
	# Comma-joined like every other fixture here (CLOUD-923's format), even though
	# this line is deliberately unrealistic — a real comment records `-` in both of
	# the last two columns. The point is that the `kind` skip happens before any
	# column is read, so an overlap that WOULD refuse still does not.
	record "comment CLOUD-900 2026-08-19T00:00:00.000Z - 1,a/one.rs -"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# CLOUD-774. THE HOLE THIS CLOSED, and the case that would have caught the punt
# that prompted it. The recorder stores the paths a row NAMES; the intersection
# happens here. Before, the count was frozen when the row was filed — and rows are
# filed before any file is touched, because AGENTS.md says claim before writing
# code — so the compliant order recorded `0` and this refusal never fired.
@test "A ROW RECORDED BEFORE THE FILE WAS TOUCHED IS STILL CAUGHT" {
	# Recorded with no diff at all: the paths are what the body named, not an
	# intersection. The edit lands afterwards, exactly as it did on the branch this
	# was found on.
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 2,a/one.rs,b/two.rs"
	changes a/one.rs b/two.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff a/one.rs"* ]]
}

# The intersection is real, not a pass-through of the recorded list: a row may
# name a dozen files and touch one, and only the one it touches is a pointer.
@test "a recorded path the branch does not change is not reported" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 2,a/one.rs,b/untouched.rs"
	changes a/one.rs
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"a/one.rs"* ]]
	[[ "$output" != *"b/untouched.rs"* ]]
}

@test "a row naming only files this branch leaves alone passes" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,b/untouched.rs"
	changes a/one.rs
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# THE EXEMPTION, and without it this change would punish the honest path: a row
# filed AND THEN FIXED on the same branch has its paths in the diff by
# construction, so every file-then-fix would need the override.
@test "A ROW THE PR CLOSES IS EXEMPT — filing then fixing is the point, not the punt" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	changes a/one.rs
	run bash -c 'printf "Closes CLOUD-900\n" | "$1"' _ "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

@test "closing a different row does not exempt this one" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	changes a/one.rs
	run bash -c 'printf "Closes CLOUD-901\n" | "$1"' _ "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff a/one.rs"* ]]
}

# A body that merely MENTIONS the key hands the board nothing, so it cannot buy an
# exemption either — the distinction `closing-key-check` already draws, reused by
# calling it rather than by copying its match.
@test "a body that only refs the row does not exempt it" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	changes a/one.rs
	run bash -c 'printf "Refs CLOUD-900 for context\n" | "$1"' _ "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-over-own-diff a/one.rs"* ]]
}

# THE REFUSAL HAS NO PROSE REMEDY, which is the load-bearing difference from
# `filed-unrefined`: a Ready block is payable in typing and this is not.
@test "the diff refusal names four remedies and none of them is writing more prose" {
	changes a/one.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	run "$GATE"
	[[ "$output" == *"Fix it here"* ]]
	[[ "$output" == *"comment there"* ]]
	[[ "$output" == *"after this lands"* ]]
	[[ "$output" == *"BATTEN_FILED_HERE_OVERLAP=1"* ]]
	[[ "$output" != *"ready-lint"* ]]
}

# POINTER, NEVER PAYLOAD (rule 4): a path is all the recorder ever wrote, so a
# path is all this can name.
@test "the diff refusal carries the id and one path and nothing else" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	run "$GATE"
	[[ "$output" != *"2026-08-19T00:00:00.000Z"* ]]
}

# --- the override --------------------------------------------------------------
#
# Not folded into `BATTEN_FILED_HERE_BYPASS`: "this record is unreadable" and "I
# meant to file this row against code I have open" are different decisions, and
# the second is legitimate often enough — a row documenting the change you are
# landing — to need a route that is not a blanket off-switch.

@test "the override lets the diff refusal through" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs"
	run env BATTEN_FILED_HERE_OVERLAP=1 "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# THE ONLY THING THAT MAKES IT WORTH HAVING. A blanket off-switch and a recorded
# decision look identical to the branch and completely different to a reviewer.
@test "the override records which rows it overrode" {
	changes a/one.rs b/two.rs
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1,a/one.rs" \
		"issue CLOUD-901 2026-08-19T00:00:00.000Z ready 1,b/two.rs"
	run env BATTEN_FILED_HERE_OVERLAP=1 "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"BATTEN_FILED_HERE_OVERLAP"* ]]
	[[ "$output" == *"CLOUD-900"* ]]
	[[ "$output" == *"CLOUD-901"* ]]
	run cat "$REPO/.git/batten-receipts/filed-here-overrides.work"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-900 CLOUD-901"* ]]
}

# It is the DIFF override, not a bypass: a row filed unrefined is still refused.
@test "the override does not excuse an unrefined row" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z unready 1,a/one.rs"
	run env BATTEN_FILED_HERE_OVERLAP=1 "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-900 filed-unrefined"* ]]
	[[ "$output" != *"filed-over-own-diff"* ]]
}

# And it writes nothing when it overrode nothing — a receipt for a decision
# nobody made reads as a decision somebody made.
@test "the override records nothing when there was nothing to override" {
	record "issue CLOUD-900 2026-08-19T00:00:00.000Z ready 0"
	run env BATTEN_FILED_HERE_OVERLAP=1 "$GATE"
	[ "$status" -eq 0 ]
	[ ! -e "$REPO/.git/batten-receipts/filed-here-overrides.work" ]
}
