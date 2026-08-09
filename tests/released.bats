#!/usr/bin/env bats
# The predicate behind In Review -> Done (CLOUD-174), and its refusal (CLOUD-257).
#
# `released` resolves refs from a tag's commit range, so it answers "did a tag
# ship a commit naming this issue" — not "is this issue finished". Used as the
# sole authority on a TERMINAL transition that closes work that is still open;
# measured, it reported CLOUD-108 and CLOUD-202 as movable when neither was done.
# Remaining scope is not computable from git, so the mechanism is the refusal: an
# issue carrying the hold marker is reported HELD and the run exits 1.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/released"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || return 1
	git init -q -b main .
	git config user.email t@example.com
	git config user.name t
	git config commit.gpgsign false
	commit "feat: the first thing" "Refs: CLOUD-1"
	git tag v0.0.1
	commit "feat: the second thing" "Refs: CLOUD-2"
	commit "fix: the third thing" "Refs: CLOUD-3"
	git tag v0.0.2
}

commit() {
	git commit -q --allow-empty -m "$1" -m "${2:-}"
}

# A payload set, one {id,status,description} per issue.
payload() {
	local out="[" first=1 spec id status body
	for spec in "$@"; do
		id="${spec%%:*}"
		status="${spec#*:}"
		body="${status#*:}"
		status="${status%%:*}"
		[ "$body" != "$spec" ] || body=""
		[ "$first" = 1 ] || out="$out,"
		first=0
		out="$out{\"id\":\"$id\",\"status\":\"$status\",\"description\":\"$body\"}"
	done
	printf '%s]' "$out]" | sed 's/]]$/]/'
}

@test "with no stdin it reports what the tag shipped" {
	run bash -c "'$TASK' v0.0.2 </dev/null"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2"* ]]
	[[ "$output" == *"CLOUD-3"* ]]
	# Scoped to the range, so the previous tag's issue is not re-reported.
	[[ "$output" != *"CLOUD-1"* ]]
}

@test "an In Review issue the tag shipped is movable" {
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" == *"1 to move"* ]]
}

@test "an issue in any other state is left alone, never touched" {
	run bash -c "printf '%s' '$(payload CLOUD-2:Done)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" != *"-> Done"* ]]
}

@test "THE REFUSAL: an issue holding itself open is HELD, not movable" {
	# CLOUD-108's shape. Its body says DO NOT CLOSE UNTIL THE MATRIX HAS RUN
	# GREEN and names closing on \"the commits released\" as the exact trap; the
	# sweep reported it movable anyway, and it was moved and reverted.
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:blocked,\ DO-NOT-CLOSE\ until\ the\ matrix\ is\ green)' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  HELD"* ]]
	[[ "$output" == *"0 to move"* ]]
	[[ "$output" == *"1 HELD"* ]]
}

@test "the refusal says why shipping is not enough, not merely that it refused" {
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:DO-NOT-CLOSE)' | '$TASK' v0.0.2"
	[[ "$output" == *"necessary for Done, not sufficient"* ]]
}

@test "a held issue does not suppress the movable ones beside it" {
	# The report must stay complete: a caller acts on what it can and resolves
	# the hold separately. Swallowing the movable list would make the refusal
	# cost more than it saves, and it would get bypassed.
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:DO-NOT-CLOSE CLOUD-3:In\ Review)' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  HELD"* ]]
	[[ "$output" == *"CLOUD-3  In Review -> Done"* ]]
}

@test "the marker only holds an In Review issue — a Done one is already past it" {
	run bash -c "printf '%s' '$(payload CLOUD-2:Done:DO-NOT-CLOSE)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" != *"HELD"* ]]
}

@test "an issue with no marker and no description still moves" {
	# The marker is opt-in: a body that does not carry it keeps the old answer,
	# so this cannot quietly freeze the whole board.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"In Review -> Done"* ]]
}

@test "a tag that does not exist is exit 2, not an empty release" {
	run "$TASK" v9.9.9
	[ "$status" -eq 2 ]
}

@test "stdin that is not a payload set is exit 2, distinct from a stale board" {
	run bash -c "printf 'not json' | '$TASK' v0.0.2"
	[ "$status" -eq 2 ]
}

@test "the marker is stated once, in the task, not spread across issue prose" {
	# One authority for the token (§1): an issue adds a hold by copying a string
	# the task defines, rather than inventing a phrasing the task must recognise.
	run grep -c "^HOLD_MARKER=" "$TASK"
	[ "$output" -eq 1 ]
}
