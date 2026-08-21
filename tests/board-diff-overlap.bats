#!/usr/bin/env bats
# subject: mise-tasks/board-diff-overlap.sh
# CLOUD-514, phase 3. The sensor that answers "how many paths does this row's
# body name that the branch is also changing".
#
# Every test runs inside a throwaway `git init` for `board-write-record.bats`'s
# reason and one more: the subject reads `origin/main...HEAD` and `git ls-files`,
# so a suite running in this checkout would be measured against the real
# session's own diff and its verdicts would change commit by commit.

setup() {
	SENSOR="$BATS_TEST_DIRNAME/../mise-tasks/board-diff-overlap.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	rm -rf "$REPO"
	mkdir -p "$REPO/src" "$REPO/other" "$REPO/mise-tasks"
	git -C "$REPO" init --quiet --initial-branch=main
	# Per fixture, never inherited — a CI runner carries no global identity, so a
	# bare `git commit` here fails only there (CLOUD-513).
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	printf 'a\n' >"$REPO/src/git.rs"
	printf 'b\n' >"$REPO/src/lint.rs"
	# The ambiguity fixture: one basename, two tracked paths.
	printf 'c\n' >"$REPO/src/mod.rs"
	printf 'd\n' >"$REPO/other/mod.rs"
	printf 'e\n' >"$REPO/mise-tasks/macos-link-check.sh"
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m base
	git -C "$REPO" update-ref refs/remotes/origin/main HEAD
	git -C "$REPO" checkout -q -b work
	cd "$REPO" || return 1
}

# Stage a change to each named path and commit it, so `origin/main...HEAD` has
# exactly that set.
changing() {
	local path
	for path in "$@"; do printf 'changed\n' >>"$REPO/$path"; done
	git -C "$REPO" commit -q -am change
}

# --- what it sees --------------------------------------------------------------

# THE CASE THE WHOLE DESIGN TURNS ON. Bodies here write `git.rs:107`, never
# `src/git.rs`: measured against the three rows this was built from, exact path
# matching finds ZERO and basename resolution finds all three. A sensor matching
# only tracked paths would have shipped blind to its own corpus.
@test "a short form resolves to the tracked path" {
	changing src/git.rs
	run bash -c "printf '%s' 'The refusal is at git.rs:107.' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "1 src/git.rs" ]
}

@test "a full tracked path resolves too" {
	changing src/git.rs
	run bash -c "printf '%s' 'See src/git.rs for the shape.' | '$SENSOR'"
	[ "$output" = "1 src/git.rs" ]
}

# A task file has no extension at all, so neither of the two shapes above reaches
# it. Bodies name one in backticks; that is the third arm.
@test "a backticked task name with no extension resolves" {
	changing mise-tasks/macos-link-check.sh
	run bash -c "printf '%s' 'The gate is \`macos-link-check\`.' | '$SENSOR'"
	[ "$output" = "1 mise-tasks/macos-link-check.sh" ]
}

@test "two named changed files are both reported, sorted" {
	changing src/git.rs src/lint.rs
	run bash -c "printf '%s' 'Both git.rs and lint.rs are wrong.' | '$SENSOR'"
	[ "$output" = "2 src/git.rs src/lint.rs" ]
}

# --- what it must NOT see ------------------------------------------------------

# THE OTHER DIRECTION (CLOUD-418). The intersection is with what the branch
# CHANGES, not with what it tracks: a sensor that dropped that term would refuse
# every row naming any file in the repository, which is a gate nobody can work
# under and therefore a gate that gets switched off.
@test "a row naming only untouched files reports nothing" {
	changing src/git.rs
	run bash -c "printf '%s' 'The bug is in lint.rs:12.' | '$SENSOR'"
	[ "$output" = "0" ]
}

# The same body against a branch holding nothing open. Filing after landing, from
# a clean tree, is one of the four remedies the gate prints — so it has to be a
# remedy the sensor actually honours.
@test "the same body reports nothing once the branch changes nothing" {
	run bash -c "printf '%s' 'The refusal is at git.rs:107.' | '$SENSOR'"
	[ "$output" = "0" ]
}

# GUESSING IS A WRONG ANSWER WEARING A RIGHT ANSWER'S SHAPE. `mod.rs` names two
# tracked files here; 28 of 530 tracked basenames are ambiguous in the real tree.
# An ambiguous basename resolves to nothing, the "could not look" reading this
# repo draws everywhere.
# BOTH candidates are changed here, deliberately: with only one of them in the
# diff, a sensor that guessed and happened to pick the other would report nothing
# and read as correct. Changing both leaves no wrong guess that looks right.
@test "an ambiguous basename resolves to nothing" {
	changing src/mod.rs other/mod.rs
	run bash -c "printf '%s' 'The bug is in mod.rs:3.' | '$SENSOR'"
	[ "$output" = "0" ]
}

# ...and the disambiguated form still resolves, so the rule above is a refusal to
# guess rather than a blind spot over a whole basename.
@test "the same file named by its full path resolves despite the ambiguity" {
	changing src/mod.rs
	run bash -c "printf '%s' 'The bug is in src/mod.rs:3.' | '$SENSOR'"
	[ "$output" = "1 src/mod.rs" ]
}

# A name that resolves to no tracked file at all is not an error and not a
# finding — a body may name anything.
@test "a path naming no tracked file is ignored rather than reported" {
	changing src/git.rs
	run bash -c "printf '%s' 'Compare against upstream/foo.rs and README.other.' | '$SENSOR'"
	[ "$output" = "0" ]
}

# --- pointer, never payload (non-negotiable 4) ---------------------------------

# The input is an entire issue body. The only thing that may leave this sensor is
# a path tracked in this repository, which is a structural property rather than a
# careful one: nothing else can survive the intersection.
@test "nothing from the body but a tracked path is emitted" {
	changing src/git.rs
	run bash -c "printf '%s' 'git.rs leaks hunter2 for acct 00219 at evil.example.com.' | '$SENSOR'"
	[ "$output" = "1 src/git.rs" ]
}

# --- could not look ------------------------------------------------------------

# `-` is a third answer, not a zero: the gate reads it as "not answered" and
# passes, because reporting a fact about the environment as a fact about the row
# is the confusion the record's verdict column already exists to avoid.
@test "an empty body reports a dash rather than a zero" {
	run bash -c "printf '' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "-" ]
}

@test "outside a git checkout it reports a dash" {
	cd "$BATS_TEST_TMPDIR" || return 1
	mkdir -p nowhere
	cd nowhere || return 1
	run bash -c "printf '%s' 'git.rs:107' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "-" ]
}

# A clone with no `origin/main` cannot answer either — and must not answer `0`,
# which would read as "this row names nothing you have open".
@test "a checkout with no origin/main reports a dash" {
	git -C "$REPO" update-ref -d refs/remotes/origin/main
	run bash -c "printf '%s' 'git.rs:107' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "-" ]
}

# It is a SENSOR. `filed-here-check` is the gate, and a sensor that exited
# non-zero would stop the `PostToolUse` body that calls it.
@test "it never exits non-zero, whatever it finds" {
	changing src/git.rs
	run bash -c "printf '%s' 'git.rs:107' | '$SENSOR'"
	[ "$status" -eq 0 ]
	run bash -c "printf '%s' 'nothing at all' | '$SENSOR'"
	[ "$status" -eq 0 ]
}

# --- the replay (CLOUD-514) ----------------------------------------------------
#
# THE RECALL MEASUREMENT, over the corpus that produced this sensor rather than
# over fixtures written to pass it. `tests/fixtures/board-diff-overlap/` holds
# the three rows this branch spun off on 2026-08-20 as the tracker stored them,
# the branch's tracked file list, and the diff exactly as it stood at 00:39 when
# they were filed. Reconstructing that tree and feeding the bodies back is the
# only evidence that the predicate fires on real punts and not just on shapes
# invented alongside it (CLOUD-248's precedent, CLOUD-633's obligation).
#
# EXACT PATH MATCHING FINDS ZERO OF THE THREE — measured, and the reason the
# basename arm exists at all: every body writes `git.rs:107`, never
# `crates/batten/src/git.rs`.
replay_repo() {
	local fixtures="$BATS_TEST_DIRNAME/fixtures/board-diff-overlap"
	local replay="$BATS_TEST_TMPDIR/replay" path
	rm -rf "$replay"
	mkdir -p "$replay"
	git -C "$replay" init --quiet --initial-branch=main
	git -C "$replay" config user.email t@example.com
	git -C "$replay" config user.name t
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		mkdir -p "$replay/$(dirname -- "$path")"
		printf 'base\n' >"$replay/$path"
	done <"$fixtures/tracked-at-filing.txt"
	git -C "$replay" add -A
	git -C "$replay" commit -q -m base
	git -C "$replay" update-ref refs/remotes/origin/main HEAD
	git -C "$replay" checkout -q -b work
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		printf 'changed\n' >>"$replay/$path"
	done <"$fixtures/changed-at-filing.txt"
	git -C "$replay" commit -q -am change
	printf '%s\n' "$replay"
}

@test "REPLAY: all three rows this branch spun off name code it was holding open" {
	local replay fixtures
	fixtures="$BATS_TEST_DIRNAME/fixtures/board-diff-overlap"
	replay=$(replay_repo)
	cd "$replay" || return 1

	run bash -c "'$SENSOR' < '$fixtures/CLOUD-739.md'"
	[ "$output" = "1 crates/batten/src/git.rs" ]

	run bash -c "'$SENSOR' < '$fixtures/CLOUD-740.md'"
	[ "$output" = "1 crates/batten/src/git.rs" ]

	run bash -c "'$SENSOR' < '$fixtures/CLOUD-737.md'"
	[ "$output" = "1 mise-tasks/macos-link-check.sh" ]
}

# THE CONTROL, and without it the case above is not a measurement. The same three
# bodies against a branch holding nothing open must report nothing: what fires is
# the intersection with the diff, not the mere mention of a file that exists.
@test "REPLAY CONTROL: the same three bodies report nothing from a clean tree" {
	local replay fixtures row
	fixtures="$BATS_TEST_DIRNAME/fixtures/board-diff-overlap"
	replay=$(replay_repo)
	cd "$replay" || return 1
	git checkout -q -B work refs/remotes/origin/main

	for row in 737 739 740; do
		run bash -c "'$SENSOR' < '$fixtures/CLOUD-$row.md'"
		[ "$output" = "0" ]
	done
}

# CLOUD-774. `--named` REPORTS WHAT THE BODY NAMES, WITH NO DIFF TERM. The recorder
# wants that rather than the intersection: an intersection is a fact about the diff
# at the instant the row was written, and a row is routinely written before the
# file is touched, so the frozen number was `0` for every compliant filing.
@test "--named reports a named path the branch has not changed" {
	changing src/git.rs
	run bash -c "printf 'See \`lint.rs\` for it.\n' | '$SENSOR' --named"
	[ "$status" -eq 0 ]
	[ "$output" = "1 src/lint.rs" ]
}

@test "the default mode still intersects, so the same body reports nothing" {
	changing src/git.rs
	run bash -c "printf 'See \`lint.rs\` for it.\n' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "0" ]
}

# `--named` KEEPS THE AMBIGUITY RULE: dropping the diff term must not also drop
# the refusal to guess, or the recorder would store a path nobody named.
@test "--named still resolves an ambiguous basename to nothing" {
	changing src/git.rs
	run bash -c "printf 'See \`mod.rs\` for it.\n' | '$SENSOR' --named"
	[ "$status" -eq 0 ]
	[ "$output" = "0" ]
}

# `--named` NEEDS ONLY `git ls-files`, NOT `origin/main`, and the asymmetry is
# deliberate: a container with no remote ref would otherwise record `-` for every
# row it files, losing the entry the later intersection depends on.
@test "--named works where there is no origin/main to diff against" {
	git -C "$REPO" update-ref -d refs/remotes/origin/main
	run bash -c "printf 'See \`lint.rs\` for it.\n' | '$SENSOR' --named"
	[ "$status" -eq 0 ]
	[ "$output" = "1 src/lint.rs" ]
}

@test "the default mode without origin/main is still could-not-look" {
	git -C "$REPO" update-ref -d refs/remotes/origin/main
	run bash -c "printf 'See \`lint.rs\` for it.\n' | '$SENSOR'"
	[ "$status" -eq 0 ]
	[ "$output" = "-" ]
}

@test "an unknown flag is a usage error, not a silent default" {
	run bash -c "printf 'x\n' | '$SENSOR' --nope"
	[ "$status" -eq 2 ]
}
