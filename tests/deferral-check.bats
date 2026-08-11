#!/usr/bin/env bats
# A deferred decision that lands with no ticket (CLOUD-323).
#
# The failure is measured, not imagined: two open decisions landed on `main`
# during CLOUD-164 with their only record a paragraph in a PR body, and the board
# showed a clean Done with no follow-up. They are CLOUD-321 and CLOUD-322 now
# because a human asked, not because anything checked.
#
# `.claude/rules/toolchain.md` records that `issue-guard` deliberately does not
# gate this — "not computable over any artifact the repo can see". That holds for
# the TREE and is why this gate does not live there: the artifact here is the PR
# BODY, which `gh` can see and which a caller pipes in. Same
# agents-fetch-gates-decide contract every board gate uses, so the verdict is a
# pure function of stdin and this suite needs no network.
#
# The two anchor cases are the real paragraphs the shape was measured on, so a
# change that breaks the discrimination fails against the evidence that chose it.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/deferral-check"
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

@test "the report is a pointer, never the paragraph" {
	# Rule 4, and here it is the mechanism rather than a privacy rule: handing the
	# prose back would let the finding be cleared by REWORDING it, which is the
	# mirror hazard `finding-sink-check`'s header records.
	run bash -c "printf 'That is a judgement call.\nThe reasoning runs to a second line nobody should see echoed.\n' | '$CHECK'"
	[ "$status" -eq 1 ]
	[[ "$output" != *"nobody should see echoed"* ]]
}
