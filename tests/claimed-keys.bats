#!/usr/bin/env bats
# The claim derivation, split out of `issue-guard` when `deferral-check` needed
# the same answer (CLOUD-338). Two guards disagreeing about which issue a PR
# claims would be worse than either misfiring, and a second copy is how that
# happens — so the precedence is pinned here, once, and both callers read it.
#
# WHICH issue a branch claims is narrower than which it mentions. That
# distinction is the whole point: `issue-guard` produced false positives against
# its own PR twice by conflating them, and `deferral-check` exempted a deferral
# using the key `issue-guard` had forced onto the PR.

setup() {
	KEYS="$BATS_TEST_DIRNAME/../mise-tasks/claimed-keys"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	# `git init -b`, never `git branch -f`: forcing the checked-out branch fails,
	# and CI hides it only because the runner still defaults to `master`
	# (CLOUD-282). A commit is required — an unborn branch has no HEAD to resolve.
	git init -q -b claude/cloud-777-fixture "$REPO"
	cd "$REPO" || return 1
	commit() {
		git -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
			commit -q --allow-empty -m "$1"
	}
	commit "fixture"
	# The commit sources read `origin/main..HEAD`, so the fixture needs that ref
	# or the log is empty and only the branch name ever answers. Pointing it at
	# the base commit makes every later commit part of "this branch's work".
	git update-ref refs/remotes/origin/main HEAD
}

@test "a branch naming one issue is an unambiguous claim" {
	run bash -c "'$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-777" ]
}

@test "a closing keyword on stdin overrides the branch" {
	# The escape hatch for a branch whose name no longer reflects the work.
	run bash -c "printf 'Closes CLOUD-321\n' | '$KEYS'"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-321" ]
}

@test "a closing keyword in a commit overrides the branch too" {
	commit "fix: something

Fixes CLOUD-322"
	run bash -c "'$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-322" ]
}

@test "a merely mentioned issue is not a claim" {
	# A body cites related issues and prior measurements as evidence. Neither is
	# a claim, and reading them as one is the false positive this split preserves.
	run bash -c "printf 'Builds on CLOUD-164 and supersedes CLOUD-99.\n' | '$KEYS'"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-777" ]
}

@test "a Refs: trailer claims when nothing more explicit does" {
	git checkout -q -b claude/no-key-here
	commit "fix: something

Refs: CLOUD-286"
	run bash -c "'$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-286" ]
}

@test "nothing resolvable is an empty answer, not an error" {
	# Every caller reads empty as \"do not judge\". A guard that guesses is one
	# that blocks correct work.
	git checkout -q -b claude/no-key-here
	run bash -c "'$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "outside a git checkout it exits 0 and says nothing" {
	run bash -c "cd '$BATS_TEST_TMPDIR' && '$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the answer is uppercased and deduplicated" {
	run bash -c "printf 'Closes cloud-321 and Closes CLOUD-321\n' | '$KEYS'"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-321" ]
}

@test "output is the keys alone — never the prose they came from" {
	# Rule 4. The callers report coordinates; this must not hand them a payload.
	run bash -c "printf 'Closes CLOUD-321 — the secret reasoning nobody should echo.\n' | '$KEYS'"
	[ "$status" -eq 0 ]
	[[ "$output" != *"secret reasoning"* ]]
}

# --- Explicit sources, for a PR this checkout did not author (CLOUD-378) ------
#
# `issue-guard` asks the same question about a COMPETING PR and could not,
# because every source above is read from the local repository. So it re-derived
# the answer inline as a bare mention of the key — the conflation this file
# exists to refuse, applied to the other side of the comparison.
#
# Every case below runs INSIDE the fixture repo, whose branch claims CLOUD-777.
# That is the load-bearing part: if any explicit source leaked a git read, these
# would answer CLOUD-777 and pass for the wrong reason.

@test "an explicit branch answers instead of the checkout's" {
	run bash -c "'$KEYS' --branch wenzowski/cloud-268-attribution </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-268" ]
}

@test "an explicit title is a claim, the way a branch is" {
	# This repo ends every PR title with `(CLOUD-<n>)`, so for a PR you did not
	# author the title is the other self-declaration of what the work is.
	run bash -c "'$KEYS' --title 'feat(x): a thing (CLOUD-268)' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-268" ]
}

@test "branch and title are a union, not a precedence between them" {
	run bash -c "'$KEYS' --branch claude/cloud-268-x --title 'feat: y (CLOUD-269)' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-268
CLOUD-269" ]
}

@test "a body that merely CITES a key claims nothing — the measured case" {
	# PR #306: claims CLOUD-268 by branch and title, names CLOUD-133 once in an
	# evidence table. It was reported as claiming CLOUD-133.
	run bash -c "printf '| Provenance records (CLOUD-133 fields) | CLOUD-275 |\n' | '$KEYS' --branch wenzowski/cloud-268-attribution --title 'docs(agents): the record (CLOUD-268)'"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-268" ]
}

@test "a closing keyword in an explicit body still overrides branch and title" {
	run bash -c "printf 'Closes CLOUD-321\n' | '$KEYS' --branch claude/cloud-268-x --title 'feat (CLOUD-269)'"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-321" ]
}

@test "an explicit log supplies the Refs: trailer, and only the trailer" {
	run bash -c "'$KEYS' --branch claude/no-key --title 'chore: tidy' --log 'chore: tidy
Refs: CLOUD-321' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-321" ]
}

@test "a key merely cited in an explicit log claims nothing" {
	run bash -c "'$KEYS' --branch claude/no-key --title 'chore: tidy' --log 'chore: tidy
Measured against CLOUD-321.' </dev/null"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "explicit mode is all-or-nothing — an unsupplied source is empty, never local" {
	# A remote PR silently answered from the local branch would be a confident
	# verdict about the wrong repository state, which is worse than no verdict.
	run bash -c "'$KEYS' --title 'chore: nothing here' </dev/null"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a flag with no value is exit 2, never a silently empty source" {
	run bash -c "'$KEYS' --branch </dev/null"
	[ "$status" -eq 2 ]
}

@test "an unknown argument is exit 2, and names no prose" {
	run bash -c "'$KEYS' --whatever CLOUD-321 </dev/null"
	[ "$status" -eq 2 ]
	[[ "$output" != *"CLOUD-321"* ]]
}
