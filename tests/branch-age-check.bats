#!/usr/bin/env bats
# The ticking clock on a branch's life (CLOUD-349).
#
# Both readings are injected, so every case runs offline and with no `gh`: the
# gate's job is the arithmetic and the verdict, and a suite that needed a remote
# would be testing the remote.
#
# The discipline is the one the other gates hold: a clean tree passes, each
# finding fires on its own and is NAMED, the trunk is never counted, and an
# unreadable reading is exit 2 rather than a pass. That last one is the whole
# reason this file exists — a gate that cannot look and says nothing reports
# hygiene it never measured.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/branch-age-check"
	REFS="$BATS_TEST_TMPDIR/refs.tsv"
	PRS="$BATS_TEST_TMPDIR/prs.txt"
	export BRANCH_AGE_REFS="$REFS" BRANCH_AGE_PRS="$PRS" BRANCH_AGE_TODAY=2026-08-11
	printf 'main\t2026-08-11T10:00:00Z\n' >"$REFS"
	: >"$PRS"
}

# `<branch><TAB><ISO tip date>`, the shape the GraphQL reading emits.
ref() { printf '%s\t%s\n' "$1" "$2" >>"$REFS"; }

@test "a remote carrying only fresh branches passes" {
	ref feat 2026-08-10T09:00:00Z
	printf 'feat\n' >"$PRS"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no branch older than 2d"* ]]
}

@test "a branch past the threshold is refused, and named with its age" {
	# The ordinary leftover: ten `release-plz-*` branches sat five days stale
	# when this was measured.
	ref stale-one 2026-08-01T09:00:00Z
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"stale	stale-one	10"* ]]
	[[ "$output" == *"1 branch(es) older than 2d"* ]]
}

@test "the threshold is a boundary, not a suggestion" {
	# Exactly BRANCH_MAX_AGE_DAYS old is still short-lived — the source says "a
	# couple of days", and a gate that fired AT two days would refuse the branch
	# it is meant to permit.
	ref two-days 2026-08-09T09:00:00Z
	ref three-days 2026-08-08T09:00:00Z
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"two-days"* ]]
	[[ "$output" == *"stale	three-days	3"* ]]
}

@test "a name heading more than one merged PR is refused, and counted" {
	# The half the per-PR lifetime metric cannot see: eight consecutive PRs on
	# one branch name all landed within the hour, while the branch itself
	# outlived every one of their stories.
	ref busy 2026-08-11T09:00:00Z
	printf 'busy\nbusy\nbusy\nother\n' >"$PRS"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"reused	busy	3"* ]]
	[[ "$output" == *"1 name(s) heading more than one merged PR"* ]]
	[[ "$output" != *"other"* ]]
}

@test "the trunk is never counted, however old or however many PRs it heads" {
	# `main` is the one long-lived branch by design. Counting it would make the
	# gate permanently red and therefore permanently ignored.
	printf 'main\t2020-01-01T00:00:00Z\n' >"$REFS"
	printf 'main\nmain\n' >"$PRS"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a custom threshold is honoured in both the verdict and the message" {
	ref four-days 2026-08-07T09:00:00Z
	BRANCH_MAX_AGE_DAYS=7 run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"older than 7d"* ]]
}

@test "an unreadable refs reading is exit 2, not a pass" {
	# The failure this gate exists to not have: a hygiene check that could not
	# look reports hygiene it never measured.
	BRANCH_AGE_REFS="$BATS_TEST_TMPDIR/nope" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read BRANCH_AGE_REFS"* ]]
}

@test "an unreadable PR reading is exit 2, not a pass" {
	BRANCH_AGE_PRS="$BATS_TEST_TMPDIR/nope" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read BRANCH_AGE_PRS"* ]]
}

@test "a remote reporting no branches at all is exit 2, not a pass" {
	# A repository with a trunk has at least one branch, so an empty answer is
	# a broken reading rather than a spotless remote.
	: >"$REFS"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no branches at all"* ]]
}

@test "an unparseable tip date is reported rather than silently skipped" {
	# A date the arithmetic cannot read is not a fresh branch. Counting it as
	# one is how a gate goes quietly blind to whatever changes the format.
	ref weird "not-a-date"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unreadable	weird"* ]]
}

@test "a nonsense today is exit 2, not an arithmetic answer" {
	BRANCH_AGE_TODAY=yesterday run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read today's date"* ]]
}
