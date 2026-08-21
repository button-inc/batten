#!/usr/bin/env bats
# subject: mise-tasks/deferral-check.sh
# A deferred decision that lands with no ticket (CLOUD-323).
#
# The failure is measured, not imagined: two open decisions landed on `main`
# during CLOUD-164 with their only record a paragraph in a PR body, and the board
# showed a clean Done with no follow-up. They are CLOUD-321 and CLOUD-322 now
# because a human asked, not because anything checked.
#
# `issue-guard` gates the start; this gates the finish. It does not live in the
# tree gate because nothing in the TREE carries the answer — the artifact here is
# the PR BODY, which a caller pipes in. Same agents-fetch-gates-decide contract
# every board gate uses, so the verdict is a pure function of stdin and this
# suite needs no network. `.claude/rules/toolchain.md` is the authority on where
# it sits, and is corrected in the same change.
#
# The two anchor cases are the real paragraphs the shape was measured on, so a
# change that breaks the discrimination fails against the evidence that chose it.

# The gate now asks git which issue the branch CLAIMS (CLOUD-338), so the suite
# runs against a FIXTURE repo rather than the checkout it happens to live in.
# Otherwise every verdict would depend on the branch a developer ran it from —
# the "verdict is a property of the machine" shape CLOUD-227 names. The fixture
# claims CLOUD-777, a key no real issue uses.
#
# `git init -b <name>` and never `git branch -f`: forcing a branch that is
# already checked out fails, and it passes in CI today only because the runner's
# git still defaults to `master` (CLOUD-282).
setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/deferral-check.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git init -q -b claude/cloud-777-fixture "$REPO"
	cd "$REPO" || return 1
	# An unborn branch has no HEAD to resolve, and the claim derivation reads
	# `git rev-parse --abbrev-ref HEAD` — so a fixture with no commit fails open
	# and would prove nothing. One empty commit is what makes the branch real.
	git -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
		commit -q --allow-empty -m "fixture"
}

# PR #243's paragraph: a decision deferred with no owner named. The true
# positive, and the one that became CLOUD-321.
untracked() {
	cat <<-'BODY'
		## What a reviewer should look at

		**"UUID" became a 256-bit minted hex id, and that is a judgement call.**
		It is opaque, minted-once and path-independent — every property the issue
		asks of it — and it avoids a dependency added for 128 bits of opacity.
	BODY
}

# PR #233's paragraph: the same shape, with the issue that owns it named beside
# it. Correctly exempt — this is a deferral WITH a home, which is the thing the
# rule asks for rather than the thing it forbids.
tracked() {
	cat <<-'BODY'
		## What a reviewer should look at

		**No `batten.toml` key lands with the override, and that is the judgement
		call.** Nothing in the engine mints an identity for a rule match yet, so a
		rule field controlling identity would be a field nothing reads. CLOUD-164
		owns the wiring and now records the obligation.
	BODY
}

@test "a deferral with no owner in its paragraph fails" {
	run bash -c "$(declare -f untracked); untracked | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-without-owner"* ]]
}

@test "a deferral that names its owning issue passes" {
	run bash -c "$(declare -f tracked); tracked | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "the scope is the paragraph, not the body" {
	# The load-bearing case. Body-level key presence carries NO information —
	# `issue-guard` forces a key onto every PR, so a body-scoped test fires on
	# nothing. A key in a neighbouring paragraph must not launder a deferral that
	# names no owner of its own.
	run bash -c "printf 'Refs: CLOUD-999 implements the thing.\n\nThe format is a judgement call and nobody owns it.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-without-owner"* ]]
}

@test "a paragraph is read whole, so a key on another line of it still exempts" {
	# The bug this pins: reading LINE by line instead of paragraph by paragraph
	# made every line its own scope, so the gate fired on PR #233 — disagreeing
	# with the measurement it was built from. Reproducing the corpus caught it.
	run bash -c "printf 'That is a judgement call.\nCLOUD-164 owns it.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "naming the phrase in a code span is not using it" {
	# Measured on this gate's own PR: the table row documenting the shape fired
	# as a deferral. A paragraph NAMING the phrase is not one USING it, and
	# backticked spans are neutralised the same way `gh-guard` and `issue-guard`
	# neutralise quoted spans. Being consumer #1 caught this.
	run bash -c "printf '| shape | verdict |\n| \`judgement call\` | keep |\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "a body with no deferral shape passes" {
	run bash -c "printf 'This change adds a gate.\n\nRefs: CLOUD-323\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "an empty body passes rather than erroring" {
	# Fails open on nothing to read: a PR with no body is a different defect and
	# not this gate's to report.
	run bash -c "printf '' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "the American spelling is caught too" {
	run bash -c "printf 'That is a judgment call nobody owns.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
}

@test "a deferral exempted only by the PR's own claimed issue fails" {
	# CLOUD-338, and the case measured on PR #275: the paragraph named CLOUD-286,
	# the issue the PR implemented, and was exempt — while the item it described
	# was owned by CLOUD-282, which nothing asked for. The branch claims
	# CLOUD-777 here, so naming CLOUD-777 is naming the work in hand.
	run bash -c "printf 'Whether to verify on a Mac is a judgement call, and CLOUD-777 is this PR.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-without-owner"* ]]
}

@test "a deferral naming an issue the PR does not claim passes" {
	run bash -c "printf 'That is a judgement call; CLOUD-282 owns the follow-up.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "naming both the claimed issue and a real owner passes" {
	# The exemption is \"some key that is not claimed\", not \"no claimed key\" — a
	# paragraph may legitimately cite the work in hand beside the owner it files.
	run bash -c "printf 'CLOUD-777 leaves this open and it is a judgement call; CLOUD-282 owns it.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "a closing keyword in the body claims that issue too" {
	# `claimed-keys` precedence: a closing keyword OVERRIDES the branch name, so a
	# body saying `Closes CLOUD-321` cannot then use CLOUD-321 as a deferral's home.
	run bash -c "printf 'Closes CLOUD-321\n\nThe rest is a judgement call and CLOUD-321 covers it.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-without-owner"* ]]
}

@test "outside a git checkout the narrowing fails open" {
	# No branch, no log, so no claim resolves and every verdict is what it was
	# before this narrowing existed. A gate that cannot look must not invent.
	run bash -c "cd '$BATS_TEST_TMPDIR' && printf 'A judgement call, and CLOUD-777 owns it.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "an unverified claim with no owner fails — the second measured shape" {
	# PR #275's real heading, the shape `judgement call` could not see. Measured
	# 1 firing / 0 false positives over the 60 most recent merged PRs.
	run bash -c "printf '## Residual gap — not verified here\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-without-owner"* ]]
}

@test "an unverified claim that names its owner passes" {
	run bash -c "printf 'The macOS half is not verified here; CLOUD-282 owns that run.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "a dropped candidate shape does not fire" {
	# `unproven`, `left open` and the rest measured 0 firings over the corpus and
	# were dropped rather than shipped — a branch nothing exercises is dead code
	# (CLOUD-235). This pins that they stayed out.
	run bash -c "printf 'The macOS half is unproven and left open.\n' | '$CHECK'"
	[ "$status" -eq 0 ]
}

@test "the report is a pointer, never the paragraph" {
	# Rule 4, and here it is the mechanism rather than a privacy rule: handing the
	# prose back would let the finding be cleared by REWORDING it, which is the
	# mirror hazard `finding-sink-check`'s header records.
	run bash -c "printf 'That is a judgement call.\nThe reasoning runs to a second line nobody should see echoed.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" != *"nobody should see echoed"* ]]
}
