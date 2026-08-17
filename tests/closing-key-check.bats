#!/usr/bin/env bats
# The board's In Review column is written by the tracker's merged-event
# automation, and that automation fires only for a CLOSING pull request. A PR
# that merely mentions its issue links, attaches, and moves nothing.
#
# Measured as a controlled pair on CLOUD-192 — same repo, same branch name, same
# fast-forward landing, same settings, one variable:
#
#   #398  `Refs: CLOUD-192`    merged 06:27:05   never moved
#   #400  `Closes CLOUD-192`   merged 06:59:39   In Review 06:59:41
#
# Both bodies appear below as fixtures, because a gate whose cases are invented
# can pass while the thing it was built for still fails.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/closing-key-check"
}

@test "the measured failing body — named, never closed — is refused" {
	run bash -c "printf 'Some work.\n\nRefs: CLOUD-192\n' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-192  named, not closed"* ]]
}

@test "the measured passing body — a closing keyword — is accepted" {
	run bash -c "printf 'Retracts a claim.\n\nCloses CLOUD-192\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"closes CLOUD-192"* ]]
}

@test "all three verbs in all three inflections close" {
	for verb in close closes closed fix fixes fixed resolve resolves resolved; do
		run bash -c "printf '%s CLOUD-5\n' '$verb' | $GATE"
		[ "$status" -eq 0 ]
	done
}

@test "case and the optional punctuation the integration tolerates" {
	run bash -c "printf 'CLOSES: #CLOUD-5\n' | $GATE"
	[ "$status" -eq 0 ]
	run bash -c "printf 'fixes CLOUD-5\n' | $GATE"
	[ "$status" -eq 0 ]
}

@test "the keyword and the key must be ADJACENT, not merely both present" {
	# The defect this rules out: a body that says "this fixes the flaky wait" in
	# one paragraph and carries `Refs:` in another closes nothing, and must not
	# read as though it does.
	run bash -c "printf 'This fixes the thing.\n\nRefs: CLOUD-192\n' | $GATE"
	[ "$status" -eq 1 ]
}

@test "a body that MENTIONS the marker has not used it" {
	# The bug this gate found in itself on its first live outing. PR #404 carried
	# `Closes CLOUD-192` and also documented `DO-NOT-CLOSE` in its prose; the
	# unanchored substring excused it as an opt-out, so the gate passed a body for
	# the wrong reason. Same distinction the adjacency rule draws for the verb:
	# talking about a token is not using it.
	run bash -c "printf -- '- **DO-NOT-CLOSE** opts out, reusing the token.\n\nRefs: CLOUD-192\n' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-192  named, not closed"* ]]
}

@test "a closing key wins over a marker the body merely discusses" {
	# The other half of #404: the close must be read FIRST, so an explicit
	# statement about the board cannot be overridden by prose elsewhere.
	run bash -c "printf 'Adds the DO-NOT-CLOSE opt-out.\n\nCloses CLOUD-192\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"closes CLOUD-192"* ]]
	[[ "$output" != *"declines to complete"* ]]
}

@test "DO-NOT-CLOSE opts out — a PR that does not complete its issue" {
	# Trunk-based work lands several PRs per issue (CLOUD-186); marking each
	# closing would move the issue on the first landing with the work half in,
	# which is CLOUD-468's defect. Declining is explicit, not silent.
	# On its own line, which is what using the marker looks like as against
	# mentioning it — the case above.
	run bash -c "printf 'Part 1 of 3.\n\nDO-NOT-CLOSE — the third PR completes it.\n\nRefs: CLOUD-192\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"DO-NOT-CLOSE"* ]]
}

@test "a body that both closes and opts out is reported as closing" {
	# A contradictory body, and the verdict is not a preference: the marker is
	# OURS and the closing keyword is the tracker's, so Linear will move the
	# board on the keyword whatever our opt-out says. Reporting the opt-out would
	# tell the author the board stays put when it will not.
	#
	# This is what makes the close-first ordering load-bearing rather than
	# decorative — found by mutation, which reddened nothing when the two blocks
	# were swapped.
	run bash -c "printf 'DO-NOT-CLOSE\n\nCloses CLOUD-192\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"closes CLOUD-192"* ]]
	[[ "$output" != *"declines to complete"* ]]
}

@test "the marker may name the issue it declines to close" {
	# The marker ENDS IN THE CLOSING VERB, so `DO-NOT-CLOSE CLOUD-192` matched
	# `clos(e)` followed by the key and was reported as CLOSING it — the opt-out
	# unusable in its most natural form, failing as the inverse of the author's
	# intent rather than as a refusal. Naming the issue beside the marker is what
	# a reader of the body needs, so it has to be expressible.
	run bash -c "printf 'DO-NOT-CLOSE CLOUD-192 — part 1 of 3.\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"declines to complete"* ]]
	[[ "$output" != *"the merge will move the board"* ]]
}

@test "a hyphen-prefixed verb is still not a close, wherever it appears" {
	# The boundary that fixes the marker is the same one the key scan already
	# uses, and it is not marker-specific: any hyphenated compound ending in a
	# closing verb is a word, not the tracker's keyword.
	# The marker carries the body, so this is well-formed either way; what is
	# asserted is that the hyphenated compound did not supply a close.
	run bash -c "printf 'DO-NOT-CLOSE\n\nauto-closes CLOUD-192 is not what this does.\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"declines to complete"* ]]
	[[ "$output" != *"the merge will move the board"* ]]
}

@test "an indented marker still opts out — leading whitespace is not a mention" {
	run bash -c "printf 'Part 1 of 3.\n\n  DO-NOT-CLOSE\n\nRefs: CLOUD-192\n' | $GATE"
	[ "$status" -eq 0 ]
}

@test "a body naming no key at all is the key rule's case, not this one" {
	# One rule, one authority. The engine's `pr-names-an-issue` row judges this
	# at `gh pr create`, which is earlier and cheaper. It was `issue-guard` until
	# CLOUD-446 retired that program.
	run bash -c "printf 'A body with no key.\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pr-names-an-issue rule owns that case"* ]]
}

@test "one closed key is enough, even beside a named-but-unclosed one" {
	run bash -c "printf 'Closes CLOUD-179\n\nRefs: CLOUD-17\n' | $GATE"
	[ "$status" -eq 0 ]
	# What must not happen is CLOUD-17 being reported as the closed one.
	[[ "$output" != *"closes CLOUD-17 "* ]]
}

@test "a key embedded in a longer token is not a key" {
	# The bounded match, and the case that actually discriminates it: the inner
	# extraction is greedy, so `CLOUD-1792` never yields `CLOUD-179` either way
	# and a digit-suffix fixture tests nothing. A LETTER prefix is what the
	# boundary rules out. Found by mutation — the digit case was green with the
	# boundary deleted.
	run bash -c "printf 'SUBCLOUD-17 is a different system.\n' | $GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pr-names-an-issue rule owns that case"* ]]
}

@test "several named keys are each reported, in stable numeric order" {
	run bash -c "printf 'Refs: CLOUD-10\nRefs: CLOUD-2\n' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  named"*"CLOUD-10  named"* ]]
}

@test "output is a pointer — keys and a verdict, never a line of the body" {
	run bash -c "printf 'Refs: CLOUD-5\n\ncustomer detail in the body\n' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"customer detail"* ]]
}

@test "empty stdin exits 2, distinct from a passing body" {
	run bash -c ": | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"expected a PR body"* ]]
}

@test "whitespace-only stdin exits 2 as well" {
	run bash -c "printf '   \n\n  \n' | $GATE"
	[ "$status" -eq 2 ]
}
