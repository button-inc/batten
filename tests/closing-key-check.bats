#!/usr/bin/env bats
# subject: mise-tasks/closing-key-check.sh
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
	# EVERY CASE BELOW DECLARES ITS SERVED SET, and the default is deliberately not
	# used here. The gate derives "which keys did this branch serve" from the
	# checked-out branch's commits (CLOUD-674), so a case that left it unset would
	# assert against whatever branch the suite happens to run on — green on `main`,
	# red on a bundle branch, and telling nobody which. `--served-log ''` is the
	# honest declaration for a case about the closing/marker logic: this body's
	# branch served nothing, so there is nothing to strand.
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/closing-key-check.sh --served-log ''"
	# The unqualified path, for the cases that supply their own served log.
	RAW="$BATS_TEST_DIRNAME/../mise-tasks/closing-key-check.sh"

	# PR #491's real branch — `claude/dependency-automation-bundle`, seven commits,
	# read from CLOUD-674's measurement rather than invented. The first key of each
	# `Refs:` trailer is what the branch SERVED; the rest of each line is citation.
	# First keys: 593, 655, 657, 658, 661.
	SERVED_491='Refs: CLOUD-593, CLOUD-102
Refs: CLOUD-593, CLOUD-654, CLOUD-102
Refs: CLOUD-661, CLOUD-502, CLOUD-367, CLOUD-596, CLOUD-344, CLOUD-527
Refs: CLOUD-658, CLOUD-593, CLOUD-657, CLOUD-344, CLOUD-105
Refs: CLOUD-657, CLOUD-596, CLOUD-105, CLOUD-656
Refs: CLOUD-655, CLOUD-596, CLOUD-105, CLOUD-418
Refs: CLOUD-593, CLOUD-344, CLOUD-661, CLOUD-103'
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

# ─── CLOUD-674: the body must close every key the branch SERVED ───────────────
#
# The gate held both halves of this answer and never subtracted them. Measured on
# `main` at `b2f8992`: a body naming CLOUD-655/657/658/661 in prose and closing
# only CLOUD-593 exited 0, with a passing line announcing the board would move.
# Four rows stranded, and the log indistinguishable from a body that closed all
# five.
#
# Both controls are drawn from a landed artifact — PR #491 and its branch — rather
# than from a fixture invented to suit the predicate.

@test "the positive control: PR #491's real body closes every key its branch served" {
	run bash -c "printf 'Closes CLOUD-593\nCloses CLOUD-655\nCloses CLOUD-657\nCloses CLOUD-658\nCloses CLOUD-661\n' | $RAW --served-log '$SERVED_491'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the merge will move the board"* ]]
}

@test "a body closing a strict subset of the served keys is refused" {
	# THE ACCEPTANCE CASE, and the one the mutation targets: with the subtraction
	# stubbed out this is the only case that reddens, which is why the gate could
	# ship without it for as long as it did.
	run bash -c "printf 'Cites CLOUD-655 and CLOUD-657 as evidence.\n\nCloses CLOUD-593\n' | $RAW --served-log '$SERVED_491'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-655  served, not closed"* ]]
	[[ "$output" == *"CLOUD-657  served, not closed"* ]]
	[[ "$output" == *"CLOUD-658  served, not closed"* ]]
	[[ "$output" == *"CLOUD-661  served, not closed"* ]]
	# The one it DID close must not be reported as stranded.
	[[ "$output" != *"CLOUD-593  served"* ]]
}

@test "the strand refusal names keys and a remedy, never a line of the body" {
	# Rule 4, on the new path as much as the old one.
	run bash -c "printf 'customer detail in the body\n\nCloses CLOUD-593\n' | $RAW --served-log 'Refs: CLOUD-593
Refs: CLOUD-661'"
	[ "$status" -eq 1 ]
	[[ "$output" != *"customer detail"* ]]
	[[ "$output" == *"Closes <key>"* ]]
}

@test "only the FIRST key of a Refs: trailer is served — the rest are citations" {
	# The distinction the whole predicate rests on. This branch served CLOUD-593
	# alone; CLOUD-102 and CLOUD-654 are cited beside it and must not be demanded.
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log 'Refs: CLOUD-593, CLOUD-654, CLOUD-102'"
	[ "$status" -eq 0 ]
	[[ "$output" != *"served, not closed"* ]]
}

@test "DO-NOT-CLOSE exempts the subtraction, not merely the closing form" {
	# The marker says the PR deliberately does not complete its issue, so demanding
	# it close every served key asks the question it just declined.
	run bash -c "printf 'DO-NOT-CLOSE — part 1 of 3.\n\nCloses CLOUD-593\n' | $RAW --served-log '$SERVED_491'"
	[ "$status" -eq 0 ]
	[[ "$output" != *"served, not closed"* ]]
}

@test "a branch whose commits carry no Refs: trailer is not judged" {
	# No claim means do not judge — the reading `claimed-keys` documents and every
	# caller of it takes. A gate that guessed here would block correct work.
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log 'a commit subject with no trailer at all'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the merge will move the board"* ]]
}

@test "a single-ticket PR is unaffected" {
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log 'Refs: CLOUD-593'"
	[ "$status" -eq 0 ]
}

@test "--served-log '' is distinct from the flag being absent" {
	# Empty means "this branch served nothing"; absent means "read the branch".
	# Collapsing the two would make every case above depend on the checkout.
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log ''"
	[ "$status" -eq 0 ]
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log"
	[ "$status" -eq 2 ]
	[[ "$output" == *"needs a value"* ]]
}

@test "--list decides nothing, even when keys are stranded" {
	# The flag changes what is emitted, never what is matched (CLOUD-774), and that
	# has to survive a predicate that can now refuse.
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --list --served-log '$SERVED_491'"
	[ "$status" -eq 0 ]
	[[ "$output" == "CLOUD-593" ]]
}

@test "the served set ignores a closing keyword — the comparison is not circular" {
	# `claimed-keys`' full chain answers from a closing keyword FIRST, so a served
	# set taken from it would be derived from the body it is about to be subtracted
	# from and agree with it by construction. `--refs-first-only` is what stops
	# that, and this is the case that would catch a fall-back: the log carries a
	# closing keyword for a key it does NOT serve.
	run bash -c "printf 'Closes CLOUD-593\n' | $RAW --served-log 'Closes CLOUD-999

Refs: CLOUD-661'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-661  served, not closed"* ]]
	[[ "$output" != *"CLOUD-999"* ]]
}

@test "a marker naming a key exempts THAT key and no other" {
	# CLOUD-527's per-key opt-out, and the case that stops this gate being
	# vacuous on the first real body it judged — its own. That PR served seven
	# keys and had to close five: the dispatch record it rides under and a row
	# whose disposition is to fold elsewhere must not be closed, while the other
	# five must. A bare marker admits that body by switching the subtraction off
	# entirely, which is passing a bundle for the one reason a bundle must never
	# pass: nobody checked.
	log=$'feat: a\n\nRefs: CLOUD-10, CLOUD-99\n\nfeat: b\n\nRefs: CLOUD-20\n'
	run bash -c "printf 'Closes CLOUD-10\n\nDO-NOT-CLOSE CLOUD-20 — folded elsewhere.\n' | $GATE --served-log '$log'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"closes CLOUD-10"* ]]
}

@test "a keyed marker does not excuse a key it never named" {
	# The narrowing has to be exactly as wide as the keys on the marker lines.
	# If naming one key switched the whole subtraction off, this gate would be
	# the bare marker with extra steps.
	log=$'feat: a\n\nRefs: CLOUD-10\n\nfeat: b\n\nRefs: CLOUD-20\n\nfeat: c\n\nRefs: CLOUD-30\n'
	run bash -c "printf 'Closes CLOUD-10\n\nDO-NOT-CLOSE CLOUD-20 — folded elsewhere.\n' | $GATE --served-log '$log'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-30  served, not closed"* ]]
	# The declined one must NOT be reported: it was answered, not stranded.
	[[ "$output" != *"CLOUD-20  served"* ]]
}

@test "a bare marker still declines the whole body" {
	# The several-PRs-per-issue case (CLOUD-186) the marker was built for is
	# untouched: a marker that names nothing keeps the global reading.
	log=$'feat: a\n\nRefs: CLOUD-10\n\nfeat: b\n\nRefs: CLOUD-20\n'
	run bash -c "printf 'Closes CLOUD-10\n\nDO-NOT-CLOSE — part 1 of 3.\n' | $GATE --served-log '$log'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"closes CLOUD-10"* ]]
}
