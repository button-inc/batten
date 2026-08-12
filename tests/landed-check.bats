#!/usr/bin/env bats
# The tracker's open-side automation moves an issue to In Progress when a commit
# mentions it, which is not the same predicate as "work on this issue began" —
# and it only ever moves forward into that column, never out.
#
# Observed three ways in one session: an issue correctly In Review dragged BACK
# to In Progress by a later commit; an issue left In Progress after its work
# landed; an issue started by a commit that only documented the problem.
#
# What is computable from git alone: an issue In Progress whose ref is on `main`
# has landed, and AGENTS.md defines landed-on-main as In Review.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/landed-check"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	# The developer's global git config must not reach a fixture repo
	# (CLOUD-282). `init.defaultBranch=main` is the leak this suite tripped on —
	# git refuses `branch -f` on the CHECKED-OUT branch, so a machine configured
	# the modern way failed every test in the file at setup, while CI passed only
	# because the runner's git still defaults to `master`. `commit.gpgsign` is
	# the same shape. crates/batten/tests/common/mod.rs:184-185 already does this.
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	# `-b work`, so the checked-out branch is NAMED rather than inherited. The
	# `main` created below is a second branch marking the trunk while HEAD stays
	# on the feature branch — that topology is what these cases exercise — and
	# the force-create this replaces could only ever build it by accident: it
	# works while git's default is `master`, and git REFUSES to force the branch
	# that is currently checked out, so the same line failed outright the moment
	# a developer's default was the trunk's own name. Naming the branch makes the
	# topology explicit instead of inheriting it, and `main` is then a fresh name
	# needing no force at all. `no-branch-f-main` in batten.toml keeps the old
	# form out; the literal is not spelled here, because that row is a substring
	# rule over this directory and would fire on its own explanation.
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
	git update-ref refs/remotes/origin/main main
}

# Adds a commit to main carrying $1 in its message.
land() {
	git checkout -q main
	git commit -q --allow-empty -m "$1"
	git update-ref refs/remotes/origin/main main
}

@test "an In Progress issue whose commits are on main is reported" {
	land "feat: work

Refs: CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-179\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-179  In Progress -> In Review"* ]]
}

@test "the same issue in In Review is not reported — that is the correct state" {
	land "feat: work

Refs: CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-179\",\"status\":\"In Review\"}]' | $GATE"
	[ "$status" -eq 0 ]
}

@test "an In Progress issue with nothing on main is genuinely in progress" {
	run bash -c "printf '[{\"id\":\"CLOUD-999\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no In Progress issue has commits on main"* ]]
}

@test "a prefix does not match a longer id" {
	# CLOUD-17 must not be satisfied by a commit referencing CLOUD-179.
	land "feat: work

Refs: CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-17\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 0 ]
}

@test "the pipeline does not eat the verdict" {
	# `git log | grep -q` under pipefail returns the SIGPIPE status even when the
	# grep matches, so an earlier version found nothing and reported a clean
	# board. The log is read once into a variable instead.
	land "feat: a

Refs: CLOUD-1"
	land "feat: b

Refs: CLOUD-2"
	land "feat: c

Refs: CLOUD-3"
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 1 ]
}

@test "several issues are each judged, in stable order" {
	land "feat: a

Refs: CLOUD-2"
	land "feat: b

Refs: CLOUD-10"
	run bash -c "printf '[{\"id\":\"CLOUD-10\",\"status\":\"In Progress\"},{\"id\":\"CLOUD-2\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-10"* ]]
	[[ "$output" == *"CLOUD-2"* ]]
}

@test "issues in other columns are none of this gate's business" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"Todo\"},{\"id\":\"CLOUD-5\",\"status\":\"Done\"}]' | $GATE"
	[ "$status" -eq 0 ]
}

@test "output is a pointer — identifiers and target state, never issue bodies" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"In Progress\",\"description\":\"customer detail\"}]' | $GATE"
	[[ "$output" != *"customer detail"* ]]
}

@test "a concatenated payload stream is accepted, like graph-check's" {
	land "feat: work

Refs: CLOUD-5"
	run bash -c "printf '{\"id\":\"CLOUD-5\",\"status\":\"In Progress\"}' | $GATE"
	[ "$status" -eq 1 ]
}

@test "an unresolvable origin/main exits 2 — a checkout problem, not a clean board" {
	git update-ref -d refs/remotes/origin/main
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"checkout problem"* ]]
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
