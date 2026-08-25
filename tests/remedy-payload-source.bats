#!/usr/bin/env bats
# subject: mise-tasks/board-payloads.sh batten.toml
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
	# BOTH board-write refusals now live in the committed authority: the search one
	# moved there when CLOUD-312's row 1 retired and the read one when row 2 did,
	# so both are sliced like the claim row rather than out of a script. The
	# PREDICATE is unchanged and that is the point: this suite asks whether the
	# message names a source that works on any host, and where the message lives is
	# not what it is about.
	READ_GUARD=$(awk '/^id = "an-update-owes-a-recent-read"/{f=1} f&&/^reason = """/{c=1} c{print} c&&/"""$/&&!/^reason/{exit}' batten.toml)
	SEARCH_GUARD=$(awk '/^id = "filing-needs-a-search"/{f=1} f&&/^reason = """/{c=1} c{print} c&&/"""$/&&!/^reason/{exit}' batten.toml)
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
	# both — all four do — but the capture store is the required one.
	#
	# The RUNNABLE shape, not just the prefix: a message saying "batten capture"
	# and stopping there sends the reader to a subcommand list, which is the same
	# dead end one step later. `show` names the verb and `--raw` is what makes the
	# bytes pipeable — without it the reader gets a pointer, not a payload.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW" "$ABSENT"; do
		[[ "$msg" == *"batten capture show"* ]]
		[[ "$msg" == *"--raw"* ]]
	done
}

@test "every --grep in a remedy carries a pattern, since a bare flag is not a command" {
	# The recipe is only followable if each command can be typed as written. A
	# `--grep` with no argument reads as complete and is not, which is this row's
	# own defect one level down — found by review on the first push.
	# Two failures, found one after the other by review, and the second is the
	# one that survives the first fix:
	#
	#   1. "--grep`" — the flag closing a code span with nothing inside it.
	#   2. `--grep <a title the search returned>` — an argument that IS there and
	#      is MULTI-WORD and UNQUOTED. Typed as written the shell hands `--grep`
	#      only the first word and treats the rest as stray arguments, so the
	#      command is still not typeable. An unquoted single token happens to
	#      work, but a recipe that is correct only for values without spaces is
	#      the same trap one input away.
	#
	# So the assertion is that the value after `--grep ` is QUOTED, which covers
	# both: a bare flag has no quote after it either.
	local msg after
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW" "$ABSENT"; do
		[[ "$msg" == *"--grep"* ]] || continue
		[[ "$msg" != *'--grep`'* ]]
		after="${msg#*--grep }"
		# The two guards are jq programs, so a double quote is SOURCE-escaped as
		# \" and this slice sees the backslash first. The rendered deny carries a
		# bare quote. Strip one leading backslash so the assertion is about what
		# the agent reads rather than about how the file spells it.
		after="${after#\\}"
		[[ "${after:0:1}" == "'" || "${after:0:1}" == '"' ]]
		# AND the flag has to belong to a command. A floating `--grep '…'` with
		# no `capture show <handle>` in front of it is not typeable either — the
		# third review round caught exactly that in the claim row, where the
		# lookup step had been abbreviated to the flag alone. Checking the tail
		# of the prefix keeps it local to one command rather than matching a
		# `capture show` mentioned three sentences earlier.
		local prefix
		prefix="${msg%%--grep*}"
		[[ "${prefix: -60}" == *"capture show"* ]]
	done
}

@test "the absent-transcript path spells the recipe, since that is where the agent lands" {
	# Every gate above sends the reader to `board-payloads`, so this is the one
	# message that has to carry the commands rather than a pointer to them.
	[[ "$ABSENT" == *"batten capture list"* ]]
	[[ "$ABSENT" == *"--raw"* ]]
	[[ "$ABSENT" == *"--grep"* ]]
}

@test "the search recipe is followable in the ZERO-HIT case its own text blesses" {
	# The fourth review round, and the sharpest of them, because the message
	# refutes itself: it says in one paragraph that a search returning nothing
	# still mints the receipt, and in another that the way to find the capture is
	# to grep for a title the search returned. A zero-hit response carries no
	# title, so in exactly the case the gate calls legitimate the lookup step
	# cannot be typed at all.
	#
	# The pattern therefore has to identify the response by its SHAPE rather than
	# by its contents. `hasNextPage` is a pagination key: present in every
	# list_issues payload whatever the hit count, and absent from a get_issue
	# payload, so it discriminates the response KIND. Measured across every
	# capture in this session's store — 14 search payloads carried it, no
	# get_issue payload did — rather than assumed from the schema.
	#
	# Asserted as a property, not as the literal token: any pattern drawn from the
	# QUERY rather than from the RESULTS would reintroduce the defect, and the
	# thing that must not regress is that a zero-hit search stays recoverable.
	[[ "$SEARCH_GUARD" == *"hasNextPage"* ]]
	# And the text still has to SAY a zero-hit search is fine, or the two halves
	# have drifted apart again in the other direction — a recipe that works on an
	# empty response is no use if the gate has quietly started refusing one.
	[[ "$SEARCH_GUARD" == *"zero hits"* ]]
	# The claim and read rows key on an issue id, which every get_issue payload
	# carries by construction, so they have no zero-hit case to answer. Stated so
	# a reader does not add a symmetric assertion that cannot hold.
	[[ "$CLAIM_ROW" == *"CLOUD-N"* ]]
}

@test "no message invites the agent to re-type a payload" {
	# The failure mode the capture store exists to avoid, and the one an agent
	# reaches for once the sanctioned route refuses. Stated, not implied.
	# All four, including ABSENT: that is the message an agent reads at the exact
	# moment the sanctioned route has just refused, which is when re-typing looks
	# most reasonable. Leaving it out covered three of the four places the
	# temptation arises.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW" "$ABSENT"; do
		[[ "$msg" == *"re-type"* ]]
	done
}

@test "the capture route is described as equally valid, not as a fallback to apologise for" {
	# A remedy that hedges the working route gets read as second best and skipped.
	# The bytes come from the tracker either way, which is the whole argument.
	# One canonical phrasing across all four rather than three saying it and the
	# claim row saying something adjacent — asymmetry here is how a message drifts
	# out of the set without any case noticing.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW" "$ABSENT"; do
		[[ "$msg" == *"bytes the tracker returned"* ]]
	done
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
	# THAT DAY CAME. Row 1 retired and this narrowed to one body; row 2 retired and
	# there is no body left — both refusals are `reason` fields in `batten.toml`,
	# where TOML owns the quoting and no shell can be terminated by an apostrophe.
	# So the case inverts rather than being deleted: it asserts the hazard is
	# STRUCTURALLY GONE, which is a stronger claim than any wording rule, and it
	# reddens if a mediated deny is ever built by a shell body again.
	#
	# `board-payloads` is not in the set: it is a `mise run` task whose refusal goes
	# to stderr, not a `PreToolUse` body building a decision document, so an
	# apostrophe there is a message and not a parse error. Its own syntax is still
	# checked, because it is the one remedy in the corpus that is still a program.
	local msg
	for msg in "$READ_GUARD" "$SEARCH_GUARD" "$CLAIM_ROW"; do
		# A `reason` field, which is what makes the trap unreachable: the slices
		# above are taken from the config, and each really is a TOML string.
		[[ "$msg" == *'reason = """'* ]]
	done
	run bash -n mise-tasks/board-payloads.sh
	[ "$status" -eq 0 ]
}
