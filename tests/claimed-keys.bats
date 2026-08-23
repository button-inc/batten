#!/usr/bin/env bats
# subject: mise-tasks/claimed-keys.sh
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
	KEYS="$BATS_TEST_DIRNAME/../mise-tasks/claimed-keys.sh"
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

# --- the commits a speculation lent this branch (CLOUD-748) -------------------
#
# `land` speculatively rebases a waiting branch onto the lease holder's published
# head, which by design puts another branch's unlanded commits into this one's
# history. Those commits carry the holder's keys, and the holder has an open PR by
# construction — so `claim-race-check`, reading this file, reported the waiter as
# racing the very PR the bet was placed on. Measured twice in one session.
#
# `BATTEN_SPEC_BASE` is the commit the branch was replayed ONTO, exported by
# `land` while the bet is live.

# Replays the speculation's shape: the holder's keyed commit, then this branch's
# own work on top, with the boundary between them named.
# A KEYLESS BRANCH, which is what the incident ran on. `claimed-keys` ranks the
# branch name above a `Refs:` trailer, so a fixture whose branch names an issue
# answers from the branch under either arm and cannot discriminate — the first
# version of these rows did exactly that and the mutation survived. The branch
# that hit this in production was `claude/mcp-grants-bundle-xpji8t`, which carries
# no key at all, and that is precisely why the adopted trailer got to decide.
speculate_onto() { # speculate_onto <holder-commit-subject>
	git checkout -q -b claude/keyless-bundle
	commit "$1"
	SPEC_BASE=$(git rev-parse HEAD)
	commit "some work of this branch's own"
}

@test "a key carried only by a speculated commit is not claimed" {
	# THE DISCRIMINATOR (CLOUD-418, CLOUD-748 §7b). Before the boundary existed no
	# fixture could express an adopted commit at all; `mise run mutant` drives this
	# red through `claimed-keys-adopts-speculated`.
	speculate_onto "fix(git): something else entirely

Refs: CLOUD-718"
	run bash -c "BATTEN_SPEC_BASE='$SPEC_BASE' '$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	# Nothing claims: the branch carries no key and the only keyed commit is the
	# holder's. Under the mutation the range widens back and CLOUD-718 appears,
	# which is the waiter racing the PR it is waiting on.
	[ -z "$output" ]
}

@test "a key this branch authored is still claimed with a speculation live" {
	# The CLOUD-230 race must keep being caught: narrowing the range must not
	# narrow it past this branch's own commits.
	speculate_onto "fix(git): the holder's work

Refs: CLOUD-718"
	commit "feat: mine

Closes CLOUD-999"
	run bash -c "BATTEN_SPEC_BASE='$SPEC_BASE' '$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-999" ]
}

@test "with no speculation live the answer is exactly what it was" {
	commit "fix: work

Closes CLOUD-555"
	run bash -c "'$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-555" ]
}

# A STALE EXPORT MUST NOT NARROW THE SET, and the failure direction is the point:
# an unwound bet, a dead `land`, or an inherited variable from an unrelated run
# all fail the ancestry test and fall back to `origin/main`. Falling back to the
# WIDER set refuses; silently narrowing would stop catching races.
@test "a spec base that is not an ancestor of HEAD is ignored" {
	commit "feat: mine

Closes CLOUD-999"
	run bash -c "BATTEN_SPEC_BASE=0000000000000000000000000000000000000000 '$KEYS' </dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "CLOUD-999" ]
}

# --- CLOUD-804: --closing-only, for a caller asking about a LOG ----------------
#
# `landed-check` asks "which keys does main's history CLAIM". The branch-name and
# `Refs:` fallbacks answer "what does this branch claim", which is a different
# question — and source 3 in particular is the exact citation signal CLOUD-480
# was swept to In Review on. Opt-in, so every existing caller keeps the chain.

@test "--closing-only does not fall through to a Refs: trailer" {
	run "$KEYS" --closing-only --log "Refs: CLOUD-7" --branch "" --title "" </dev/null
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "--closing-only does not fall through to the branch name" {
	run "$KEYS" --closing-only --log "" --branch "wenzowski/cloud-7-a-thing" --title "" </dev/null
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "--closing-only still answers on a closing keyword" {
	run "$KEYS" --closing-only --log "Closes CLOUD-9" --branch "" --title "" </dev/null
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-9"* ]]
}

@test "without --closing-only the fallback chain is unchanged" {
	run "$KEYS" --log "Refs: CLOUD-7" --branch "" --title "" </dev/null
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-7"* ]]
}

@test "--closing-only reads the log from stdin, which is how a 1.27MB history fits" {
	# argv cannot carry main's log: measured 1272329 bytes, `Argument list too
	# long`, exit 126 and zero keys — which a caller would read as "nothing
	# claimed" (CLOUD-804).
	run bash -c "printf 'Closes CLOUD-9' | $KEYS --closing-only --branch '' --title '' --log ''"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-9"* ]]
}

# ─── CLOUD-674: source 3 in isolation ────────────────────────────────────────

@test "--refs-first-only ignores a closing keyword in the body" {
	# The circularity this flag exists to break. `closing-key-check` asks which
	# keys a branch SERVED so it can subtract the keys the body CLOSES; if the
	# served answer fell back to a closing keyword it would be derived from the
	# very body it is about to be compared with, and agree with it by
	# construction — so the gate would pass on exactly the bodies it must refuse.
	#
	# The log below closes a key it does not serve. Only the `Refs:` first key may
	# come back.
	run "$KEYS" --refs-first-only --branch "" --title "" --log 'Closes CLOUD-999

Refs: CLOUD-661, CLOUD-102'
	[ "$status" -eq 0 ]
	[[ "$output" == "CLOUD-661" ]]
}

@test "--refs-first-only takes the first key of the trailer, not its citations" {
	run "$KEYS" --refs-first-only --branch "" --title "" --log 'Refs: CLOUD-593, CLOUD-654, CLOUD-102'
	[ "$status" -eq 0 ]
	[[ "$output" == "CLOUD-593" ]]
}

@test "--refs-first-only ignores the branch name too" {
	# Source 2 is a self-declaration about which issue is being worked; it says
	# nothing about which rows the commits served, and a bundle branch is keyless
	# by construction (CLOUD-661).
	run "$KEYS" --refs-first-only --branch "claude/cloud-42-something" --title "" --log 'Refs: CLOUD-661'
	[ "$status" -eq 0 ]
	[[ "$output" == "CLOUD-661" ]]
}

@test "--refs-first-only with no trailer answers empty, which is 'do not judge'" {
	run "$KEYS" --refs-first-only --branch "" --title "" --log 'a subject with no trailer'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the two narrowing flags are mutually exclusive" {
	# Each names a different single source, so both together is a caller that has
	# not decided which question it is asking — not an intersection to compute.
	run "$KEYS" --closing-only --refs-first-only --log 'Refs: CLOUD-661'
	[ "$status" -eq 2 ]
	[[ "$output" == *"pick one"* ]]
}
