#!/usr/bin/env bats
# subject: mise-tasks/board-payloads.sh mise-tasks/issue-read-guard.sh mise-tasks/issue-search-guard.sh batten.toml
# CLOUD-990. Three gates refuse a board write and each names the same remedy —
# "pipe the get_issue payload to <check>" — while saying nothing about where the
# bytes come from. The one task that answers that, `board-payloads`, reads a
# transcript, and a CCR container writes none. So on that host the whole remedy
# chain dead-ends, and `board-payloads`' own header forecloses the workaround in
# the strongest terms ("a paraphrase into a gate payload is the forged-compliance
# shape CLOUD-526 measured seven times").
#
# Measured before this suite existed: an agent read all of that correctly and
# concluded the board could not be written from this host. It reported a blocker
# twice, then found it could not even FILE that finding, because the filing gate
# wants the same bytes. The capture store (CLOUD-919/918) had held the answer the
# whole time.
#
# So this is CLOUD-871's thesis with a mechanism: remedy prose steers the agent,
# and a remedy naming an unreachable route steers it into a stall. The predicate
# is deliberately narrow — every one of the four messages must name the source
# that works on ANY host. It says nothing about the rest of the wording.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	# The refusal text of each gate, read from the file that owns it. Sliced
	# rather than executed: two of the three are PreToolUse hooks whose refusal
	# is a JSON envelope, and running them needs a payload and a branch state
	# this suite has no business creating.
	READ_GUARD=$(awk '/permissionDecisionReason/,/^  }$/' mise-tasks/issue-read-guard.sh)
	SEARCH_GUARD=$(awk '/permissionDecisionReason/,/^  }$/' mise-tasks/issue-search-guard.sh)
	CLAIM_ROW=$(awk '/^id = "claim-needs-receipt"/{f=1} f&&/^reason = """/{c=1} c{print} c&&/"""$/&&!/^reason/{exit}' batten.toml)
	ABSENT=$(awk '/no readable transcript/,/^fi$/' mise-tasks/board-payloads.sh)
}

@test "every message was found at all — this suite is not passing vacuously" {
	[ -n "$READ_GUARD" ]
	[ -n "$SEARCH_GUARD" ]
	[ -n "$CLAIM_ROW" ]
	[ -n "$ABSENT" ]
	# Each slice really is the refusal, not a neighbouring block.
	[[ "$READ_GUARD" == *"issue-read-check"* ]]
	[[ "$SEARCH_GUARD" == *"issue-search-check"* ]]
	[[ "$CLAIM_ROW" == *"claim-check"* ]]
	[[ "$ABSENT" == *"not an empty harvest"* ]]
}

@test "THE PREDICATE: every refusal names the source that works on any host" {
	# `batten capture` rather than `board-payloads`, because the whole finding is
	# that naming only `board-payloads` is what dead-ends. A message may name
	# both — three of the four do — but the capture store is the required one.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW" "$ABSENT"; do
		[[ "$msg" == *"batten capture"* ]]
	done
}

@test "the absent-transcript path spells the recipe, since that is where the agent lands" {
	# Every gate above sends the reader to `board-payloads`, so this is the one
	# message that has to carry the commands rather than a pointer to them.
	[[ "$ABSENT" == *"batten capture list"* ]]
	[[ "$ABSENT" == *"--raw"* ]]
	[[ "$ABSENT" == *"--grep"* ]]
}

@test "no message invites the agent to re-type a payload" {
	# The failure mode the capture store exists to avoid, and the one an agent
	# reaches for once the sanctioned route refuses. Stated, not implied.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW"; do
		[[ "$msg" == *"re-type"* ]]
	done
}

@test "the capture route is described as equally valid, not as a fallback to apologise for" {
	# A remedy that hedges the working route gets read as second best and skipped.
	# The bytes come from the tracker either way, which is the whole argument.
	[[ "$READ_GUARD" == *"bytes the tracker returned"* ]]
	[[ "$SEARCH_GUARD" == *"bytes the tracker returned"* ]]
	[[ "$ABSENT" == *"bytes the tracker returned"* ]]
}

@test "no apostrophe reaches the two jq-built denies, which is why the wording above is what it is" {
	# THE TRAP, and it is worth a case because it fails LOUD but late and the
	# obvious phrasing walks straight into it. Both denies are jq programs inside
	# a SINGLE-QUOTED shell string, so one apostrophe — "the tracker's own bytes"
	# was the attempt — terminates the program and the guard stops parsing. It is
	# a PreToolUse hook, so the breakage surfaces as every mediated call erroring
	# rather than as a test failure, which is why the original text conspicuously
	# avoids apostrophes and why that constraint should be checkable rather than
	# folklore. shellcheck in the hk gate catches the parse; this names the cause.
	local body
	for body in mise-tasks/issue-read-guard.sh mise-tasks/issue-search-guard.sh; do
		run bash -n "$body"
		[ "$status" -eq 0 ]
		# The deny string itself, apostrophe-free.
		run awk '/permissionDecisionReason/,/^  }$/' "$body"
		[[ "$output" != *"'"* ]]
	done
}
