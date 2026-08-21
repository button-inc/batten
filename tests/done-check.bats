#!/usr/bin/env bats
# subject: mise-tasks/done-check
# `Done` on this board means released, and the tracker's GitHub integration keys
# it on the merge. Between those two events sits a whole release cycle, so every
# issue reads Done from the moment it lands — while shipped in nothing.
#
# Measured 2026-08-13: CLOUD-499 went Todo -> In Progress -> Done at merge time,
# with `main` 50 commits past the last tag. In Review, the column that window is
# supposed to occupy, was entered only by hand.
#
# What is computable from git alone: a Done issue that no release tag reaches has
# not shipped, and AGENTS.md defines landed-but-unreleased as In Review.
#
# The direction matters and these cases are chosen around it. A ref inside a tag
# is weak evidence (refs come from commit messages, which cite and defer as well
# as complete), so the gate must never confirm a Done on it; a ref nowhere near a
# tag is conclusive, so refuting is all it does.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/done-check"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	# The developer's global git config must not reach a fixture repo
	# (CLOUD-282) — `init.defaultBranch` and `commit.gpgsign` both leak in and
	# fail the suite at setup on a machine configured the modern way, while CI
	# passes on a runner whose git still defaults to `master`.
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	# `-b work`: the checked-out branch is NAMED, and `main` below is a second
	# branch marking the trunk while HEAD stays on the feature branch. That is
	# the topology these cases exercise, and it is built explicitly rather than
	# inherited from whatever git's default happens to be.
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
	git update-ref refs/remotes/origin/main main
	# Every case needs at least one tag, or it hits the no-tags precondition
	# instead of the predicate under test. That is itself asserted below.
	git tag v0.0.1 main
}

# Adds a commit to main carrying $1 in its message.
land() {
	git checkout -q main
	git commit -q --allow-empty -m "$1"
	git update-ref refs/remotes/origin/main main
}

# Cuts a release tag at the current tip of main — everything landed so far ships.
release() {
	git tag "$1" main
}

@test "a Done issue whose commits are in a release tag is left alone" {
	land "feat: work

Refs: CLOUD-168"
	release v0.0.2
	run bash -c "printf '[{\"id\":\"CLOUD-168\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
	# Exit 0 alone does not discriminate: once the tag is cut nothing is left
	# unreleased, so an issue judged `unlanded` also passes. Pin the COUNT, which
	# separates "a release shipped it" from "git had nothing to say about it".
	# Found by mutation — deleting the released guard left this case green.
	[[ "$output" == *"(0 not judged)"* ]]
	[[ "$output" != *"unlanded"* ]]
}

@test "a Done issue landed past the last tag is reported — this is the defect" {
	land "feat: work

Refs: CLOUD-499"
	run bash -c "printf '[{\"id\":\"CLOUD-499\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-499  Done -> In Review"* ]]
}

@test "landing then releasing clears the very same issue" {
	# The two-step path, in one case: the same issue that fails before the tag
	# passes after it, with nothing else changed.
	land "feat: work

Refs: CLOUD-499"
	run bash -c "printf '[{\"id\":\"CLOUD-499\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 1 ]
	release v0.0.2
	run bash -c "printf '[{\"id\":\"CLOUD-499\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"(0 not judged)"* ]]
}

@test "a Done issue no commit names is noted, not failed" {
	# Board-only work, an issue closed as a duplicate, anything predating the ref
	# convention. Git is this gate's only witness and it has nothing to say.
	run bash -c "printf '[{\"id\":\"CLOUD-99999\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-99999  unlanded"* ]]
	[[ "$output" == *"(1 not judged)"* ]]
}

@test "one released ref is enough, even with later unreleased ones" {
	# The documented bound: an issue carrying several PRs is judged by its
	# most-released ref. Half-landed work reaching Done is CLOUD-468's question,
	# and this gate must not pretend to answer it.
	land "feat: first

Refs: CLOUD-186"
	release v0.0.2
	land "feat: second

Refs: CLOUD-186"
	run bash -c "printf '[{\"id\":\"CLOUD-186\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
}

@test "a prefix does not match a longer id" {
	# CLOUD-17 must not be refuted by an unreleased commit naming CLOUD-179 —
	# and must not be excused by a released one either, so both directions of
	# the bounded match are exercised here.
	land "feat: work

Refs: CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-17\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-17  unlanded"* ]]
}

@test "issues in other columns are none of this gate's business" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"In Review\"},{\"id\":\"CLOUD-5\",\"status\":\"In Progress\"},{\"id\":\"CLOUD-5\",\"status\":\"Todo\"}]' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"Done -> In Review"* ]]
}

@test "the pipeline does not eat the verdict" {
	# `git log | grep -q` under pipefail returns the SIGPIPE status even when the
	# grep matches, so a gate built that way finds nothing and reports a clean
	# board. Both logs are read once into a variable instead.
	land "feat: a

Refs: CLOUD-1"
	land "feat: b

Refs: CLOUD-2"
	land "feat: c

Refs: CLOUD-3"
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 1 ]
}

@test "several issues are each judged, in stable numeric order" {
	land "feat: a

Refs: CLOUD-2"
	land "feat: b

Refs: CLOUD-10"
	run bash -c "printf '[{\"id\":\"CLOUD-10\",\"status\":\"Done\"},{\"id\":\"CLOUD-2\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 1 ]
	# Numeric by issue number, not lexical — CLOUD-2 before CLOUD-10.
	[[ "$output" == *"CLOUD-2  Done -> In Review"*"CLOUD-10  Done -> In Review"* ]]
}

@test "output is a pointer — identifiers and target state, never issue bodies" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"Done\",\"description\":\"customer detail\"}]' | $GATE"
	[[ "$output" != *"customer detail"* ]]
}

@test "a concatenated payload stream is accepted, like graph-check's" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '{\"id\":\"CLOUD-5\",\"status\":\"Done\"}' | $GATE"
	[ "$status" -eq 1 ]
}

@test "an unresolvable origin/main exits 2 — a checkout problem, not a clean board" {
	git update-ref -d refs/remotes/origin/main
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"checkout problem"* ]]
}

@test "a clone with no tags exits 2 — the opposite false verdict" {
	# The precondition that fails RED rather than green: with no tags nothing is
	# reachable from a release, so every Done issue would be reported and the
	# whole board would look broken. A default CI checkout fetches no tags, so
	# this is the ordinary way to hit it.
	land "feat: work

Refs: CLOUD-5"
	git tag -d v0.0.1
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"fetch problem"* ]]
	[[ "$output" != *"Done -> In Review"* ]]
}

@test "empty stdin exits 2, distinct from a clean board" {
	run bash -c ": | $GATE"
	[ "$status" -eq 2 ]
}

@test "unparseable stdin exits 2" {
	run bash -c "printf 'not json' | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"get_issue payloads"* ]]
}
