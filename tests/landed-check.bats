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
	# CLOUD-804: landedness is a disjunction and the merged-PR half is the
	# CALLER's to supply, so every case names an evidence file. Empty by
	# default — a case that means "landed via a merged PR" writes to it, and
	# the rest exercise the claim half alone against a file that says nothing.
	EV="$BATS_TEST_TMPDIR/merged-$BATS_TEST_NUMBER.tsv"
	: >"$EV"
}

# Records that a MERGED pull request $2 closed issue $1 — the evidence a caller
# gathers from PR bodies, which is where fast-forward landing puts the keyword.
merged_pr() {
	printf '%s\t%s\n' "$1" "$2" >>"$EV"
}

# Adds a commit to main carrying $1 in its message.
land() {
	git checkout -q main
	git commit -q --allow-empty -m "$1"
	git update-ref refs/remotes/origin/main main
}

@test "an In Progress issue whose commits are on main is reported" {
	land "feat: work

Closes CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-179\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-179  In Progress -> In Review"* ]]
}

@test "the same issue in In Review is not reported — that is the correct state" {
	land "feat: work

Closes CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-179\",\"status\":\"In Review\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "an In Progress issue with nothing on main is genuinely in progress" {
	run bash -c "printf '[{\"id\":\"CLOUD-999\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no In Progress issue has commits on main"* ]]
}

@test "a prefix does not match a longer id" {
	# CLOUD-17 must not be satisfied by a commit referencing CLOUD-179.
	land "feat: work

Closes CLOUD-179"
	run bash -c "printf '[{\"id\":\"CLOUD-17\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "the pipeline does not eat the verdict" {
	# `git log | grep -q` under pipefail returns the SIGPIPE status even when the
	# grep matches, so an earlier version found nothing and reported a clean
	# board. The log is read once into a variable instead.
	land "feat: a

Closes CLOUD-1"
	land "feat: b

Closes CLOUD-2"
	land "feat: c

Closes CLOUD-3"
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
}

@test "several issues are each judged, in stable order" {
	land "feat: a

Closes CLOUD-2"
	land "feat: b

Closes CLOUD-10"
	run bash -c "printf '[{\"id\":\"CLOUD-10\",\"status\":\"In Progress\"},{\"id\":\"CLOUD-2\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-10"* ]]
	[[ "$output" == *"CLOUD-2"* ]]
}

@test "issues in other columns are none of this gate's business" {
	land "feat: work

Closes CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"Todo\"},{\"id\":\"CLOUD-5\",\"status\":\"Done\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "output is a pointer — identifiers and target state, never issue bodies" {
	land "feat: work

Closes CLOUD-5"
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"In Progress\",\"description\":\"customer detail\"}]' | $GATE --merged-prs $EV"
	[[ "$output" != *"customer detail"* ]]
}

@test "a concatenated payload stream is accepted, like graph-check's" {
	land "feat: work

Closes CLOUD-5"
	run bash -c "printf '{\"id\":\"CLOUD-5\",\"status\":\"In Progress\"}' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
}

@test "an unresolvable origin/main exits 2 — a checkout problem, not a clean board" {
	git update-ref -d refs/remotes/origin/main
	run bash -c "printf '[{\"id\":\"CLOUD-5\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 2 ]
	[[ "$output" == *"checkout problem"* ]]
}

@test "empty stdin exits 2, distinct from a clean board" {
	run bash -c ": | $GATE --merged-prs $EV"
	[ "$status" -eq 2 ]
}

@test "unparseable stdin exits 2" {
	run bash -c "printf 'not json' | $GATE --merged-prs $EV"
	[ "$status" -eq 2 ]
	[[ "$output" == *"get_issue payloads"* ]]
}

# --- CLOUD-804: a citation is not a landing ------------------------------------
#
# The two fixtures below are verbatim shapes from `main`'s own log on 2026-08-20,
# both of which this gate reported as landed while the work sat in OPEN PR #579.
# They are the regression surface, so they are copied rather than invented.

@test "CLOUD-804: a commit citing an id as PRIOR ART does not land it" {
	land "feat(ci): verify the declared MSRV against the compiler it names

on the newer compiler while the published claim quietly goes false. That is
CLOUD-271's shape. This reads the DECLARED number and builds with THAT
compiler, so the two cannot silently diverge."
	run bash -c "printf '[{\"id\":\"CLOUD-271\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no In Progress issue has commits on main"* ]]
}

@test "CLOUD-804: a commit naming an id in a LIST OF PAST FAILURES does not land it" {
	land "feat(gate): prove a gate discriminates, and declare the conclusion set once

test passing on both the fixed and the broken code satisfied every other rule
here. That failed four times (CLOUD-235, CLOUD-352, CLOUD-401), the last one
live: a concurrency test written for a real race was green."
	run bash -c "printf '[{\"id\":\"CLOUD-401\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "CLOUD-804: a Refs: trailer is a mention, not a claim" {
	# CLOUD-480 was swept to In Review on exactly this and sat wrong for 4.5h.
	land "chore: adjacent work

Refs: CLOUD-480"
	run bash -c "printf '[{\"id\":\"CLOUD-480\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "CLOUD-804: a closing keyword in a commit IS a claim" {
	land "fix: the thing

Closes CLOUD-42"
	run bash -c "printf '[{\"id\":\"CLOUD-42\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-42  In Progress -> In Review"* ]]
}

# THE DIRECTION THIS IS MOST LIKELY TO GET WRONG. Fixing the over-report by
# reading commits alone would trade it for a silent UNDER-report: measured on
# this repository, only 31 of 966 commits on main carry a closing keyword,
# because fast-forward landing puts it in the PR body. CLOUD-201's `f5b9993` and
# `2bc1ede` are ancestors of main with no closing key anywhere in the log. If
# this case ever goes green by NOT reporting, the drain has stopped naming rows
# that really are behind git and nothing says so.
@test "CLOUD-804: commits on main with the key only in a MERGED PR body still land it" {
	land "fix(doctor): serialize the two repairs doctor's own graph races, behind one lock"
	merged_pr CLOUD-201 339
	run bash -c "printf '[{\"id\":\"CLOUD-201\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-201  In Progress -> In Review"* ]]
}

@test "CLOUD-804: an id named by no merged PR and no claim is live work" {
	# CLOUD-271/401's real shape: work in an OPEN PR, which never reaches the
	# evidence file, so an open PR can never read as landed.
	land "chore: unrelated"
	merged_pr CLOUD-999 123
	run bash -c "printf '[{\"id\":\"CLOUD-271\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "CLOUD-804: a prefix does not match a longer id in the evidence file" {
	merged_pr CLOUD-179 44
	run bash -c "printf '[{\"id\":\"CLOUD-17\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 0 ]
}

@test "CLOUD-804: no evidence flag is exit 2, never a clean column" {
	land "fix: the thing

Closes CLOUD-42"
	run bash -c "printf '[{\"id\":\"CLOUD-42\",\"status\":\"In Progress\"}]' | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"--merged-prs"* ]]
	[[ "$output" != *"no In Progress issue has commits on main"* ]]
}

@test "CLOUD-804: an unreadable evidence file is exit 2" {
	run bash -c "printf '[{\"id\":\"CLOUD-42\",\"status\":\"In Progress\"}]' | $GATE --merged-prs $BATS_TEST_TMPDIR/absent.tsv"
	[ "$status" -eq 2 ]
}

@test "CLOUD-804: the flag with no value is a caller bug, not empty evidence" {
	run bash -c "printf '[{\"id\":\"CLOUD-42\",\"status\":\"In Progress\"}]' | $GATE --merged-prs"
	[ "$status" -eq 2 ]
	[[ "$output" == *"needs a value"* ]]
}

@test "CLOUD-804: the report still carries no issue body" {
	land "fix: the thing

Closes CLOUD-42"
	run bash -c "printf '[{\"id\":\"CLOUD-42\",\"status\":\"In Progress\",\"description\":\"customer detail\"}]' | $GATE --merged-prs $EV"
	[ "$status" -eq 1 ]
	[[ "$output" != *"customer detail"* ]]
}
