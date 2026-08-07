#!/usr/bin/env bats
# Which issues did a release tag ship? `Done` here means released, and Linear's
# GitHub integration cannot supply that transition — it triggers on PR events,
# and "a tag now contains this commit" is not one. So the last transition of
# every issue was manual and reliably forgotten.
#
# The extraction is the predicate and gets tested; the Linear write is the
# effect and stays with the caller, the shape graph-check and ready-lint use.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/released"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	git init -q "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
}

# A commit whose message carries $1, then tag $2 if given.
ship() {
	git commit -q --allow-empty -m "$1"
	[ -n "${2:-}" ] && git tag "$2"
	return 0
}

@test "the real repo's acceptance case: v0.0.14 shipped CLOUD-29" {
	# The issue's named end-to-end case, and the only one that reads real
	# history. CI checks out without tags, so it is skipped there rather than
	# failed: a test may not depend on environment it does not control, and the
	# fixture cases below cover the range and extraction logic hermetically.
	cd "$BATS_TEST_DIRNAME/.." || return 1
	git rev-parse -q --verify refs/tags/v0.0.14 >/dev/null 2>&1 ||
		skip "no tags in this checkout"
	run "$GATE" v0.0.14 </dev/null
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-29"* ]]
}

@test "refs come from the range new in the tag, not the whole history" {
	ship "feat: earlier

Refs: CLOUD-1" v1
	ship "feat: later

Refs: CLOUD-2" v2
	run "$GATE" v2 </dev/null
	[[ "$output" == *"CLOUD-2"* ]]
	[[ "$output" != *"CLOUD-1"* ]]
}

@test "the first tag has no predecessor, so its range is the whole history" {
	ship "feat: the beginning

Refs: CLOUD-1" v1
	run "$GATE" v1 </dev/null
	[[ "$output" == *"CLOUD-1"* ]]
}

@test "a release of pure chore commits exits cleanly, not in error" {
	ship "feat: work

Refs: CLOUD-1" v1
	ship "chore: release v2" v2
	run "$GATE" v2 </dev/null
	[ "$status" -eq 0 ]
	[[ "$output" == *"no CLOUD-* issue"* ]]
}

@test "an In Review issue the tag shipped is named as movable" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"In Review\"}]' | $GATE v1"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-1  In Review -> Done"* ]]
	[[ "$output" == *"1 to move"* ]]
}

@test "an issue already Done is left alone — re-running is a no-op" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"Done\"}]' | $GATE v1"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" == *"0 to move"* ]]
}

@test "a state this does not understand is reported, never moved" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"Canceled\"}]' | $GATE v1"
	[[ "$output" == *"Canceled (left alone)"* ]]
	[[ "$output" == *"0 to move"* ]]
}

@test "an issue the tag shipped but which was not piped in is not a finding" {
	# The caller chooses the closure to judge, exactly as graph-check does.
	ship "feat: two issues

Refs: CLOUD-1 and CLOUD-2" v1
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"In Review\"}]' | $GATE v1"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 to move"* ]]
	[[ "$output" != *"CLOUD-2"* ]]
}

@test "a concatenated payload stream is accepted, like graph-check's" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf '{\"id\":\"CLOUD-1\",\"status\":\"In Review\"}' | $GATE v1"
	[ "$status" -eq 0 ]
	[[ "$output" == *"In Review -> Done"* ]]
}

@test "output is a pointer — identifiers and target state, never issue bodies" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf '[{\"id\":\"CLOUD-1\",\"status\":\"In Review\",\"description\":\"customer detail\"}]' | $GATE v1"
	[[ "$output" != *"customer detail"* ]]
}

@test "output is sorted, so re-running is byte-stable" {
	ship "feat: several

Refs: CLOUD-9, CLOUD-2, CLOUD-30" v1
	run "$GATE" v1 </dev/null
	local first second
	first=$(grep -c 'CLOUD-' <<<"$output")
	run "$GATE" v1 </dev/null
	second=$(grep -c 'CLOUD-' <<<"$output")
	[ "$first" = "$second" ]
	[[ "$output" == *"CLOUD-2"* ]]
	[[ "$output" == *"CLOUD-30"* ]]
}

@test "a missing tag is a caller error (exit 2), not an empty release" {
	ship "feat: work

Refs: CLOUD-1" v1
	run "$GATE" v99 </dev/null
	[ "$status" -eq 2 ]
	[[ "$output" == *"no such tag"* ]]
}

@test "no tag argument exits 2 with the usage" {
	run "$GATE" </dev/null
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
}

@test "unparseable stdin exits 2, distinct from a clean release" {
	ship "feat: work

Refs: CLOUD-1" v1
	run bash -c "printf 'not json' | $GATE v1"
	[ "$status" -eq 2 ]
	[[ "$output" == *"get_issue payloads"* ]]
}
