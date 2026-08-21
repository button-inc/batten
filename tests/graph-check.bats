#!/usr/bin/env bats
# graph-check's decision table (CLOUD-175): the two board predicates from
# mem:workflow/board-states as exit codes, graph coherence, and the frontier as
# a by-product. Fixtures are get_issue-shaped payloads built with jq.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/graph-check"
	BOARD="$BATS_TEST_TMPDIR/board.json"
	# EVERY CASE RUNS IN A THROWAWAY REPO, because the gate now mints the
	# board-move receipt CLOUD-512's guard reads. Run from this checkout, the
	# suite wrote adjudications into the real `.git/batten-receipts/` — receipts
	# that would authorise a live session's moves to In Review over fixture ids.
	# Measured on the first green run of the new rows.
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	cd "$REPO" || return 1
	RECEIPT="$REPO/.git/batten-receipts/board-move"
	# ONE PASSING READY BLOCK, shared by `issue` and `describe`. Since CLOUD-375 a
	# Todo issue whose block fails ready-lint is a violation, so a fixture body is
	# never neutral: a bare-prose description makes every Todo case a
	# `todo-not-ready` run, whatever rule it meant to exercise. Lifting the block
	# out is what lets a case choose — carry it and be judged on something else,
	# or omit it deliberately, as the CLOUD-375 rows below do.
	READY="**Refinement — Ready (t)**

* **Source of truth (§1).** One artifact."
}

# issue <id> <status> [assignee] [pr-url] [blocker...] — appends one payload.
issue() {
	local id="$1" status="$2" assignee="${3:-}" pr="${4:-}"
	shift 4 || shift $#
	local rel="[]"
	if [ "$#" -gt 0 ]; then
		rel=$(printf '%s\n' "$@" | jq -R '{id: .}' | jq -sc .)
	fi
	local att="[]"
	[ -n "$pr" ] && att=$(jq -nc --arg u "$pr" '[{url: $u}]')
	jq -nc --arg id "$id" --arg st "$status" --arg a "$assignee" \
		--arg ready "$READY" \
		--argjson att "$att" --argjson rel "$rel" '{
		id: $id, status: $st, attachments: $att,
		relations: {blockedBy: $rel},
		description: ("**Why**\nx.\n\n" + $ready),
		projectMilestone: {id: "m-1", name: "Phase 3"}
	} + (if $a == "" then {} else {assigneeId: $a} end)' >>"$BOARD"
}

# The same payload with `projectMilestone` omitted — which is how Linear renders
# an issue that has none, since it drops the key rather than nulling it. Separate
# from `drop_key`, which strips the field from EVERY issue and so models the other
# case entirely: a caller that projected it away (CLOUD-695).
no_milestone() {
	issue "$@"
	jq -c --arg id "$1" 'if .id == $id then del(.projectMilestone) else . end' \
		"$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

check() { run bash -c "'$CHECK' <'$BOARD'"; }
# stdout alone, for the cases that pin the frontier's bytes rather than a report.
check_out() { run bash -c "'$CHECK' <'$BOARD' 2>/dev/null"; }

# Drop a key from every payload in the board — the projection a caller makes when
# it fetches without includeRelations, or assembles the set by hand.
drop_key() {
	jq -c "del(.$1)" "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

# describe <id> <text> — give one issue a body to be judged on. The Ready block
# rides along: these fixtures are about what the PROSE claims, and a claim written
# as bare prose would be refused as `todo-not-ready` before its own rule was ever
# reached — the case would then pass or fail on the wrong verdict.
describe() {
	jq -c --arg id "$1" --arg d "$2

$READY" 'if .id == $id then .description = $d else . end' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

@test "a coherent board exits 0" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"board coherent (2 issues)"* ]]
}

@test "an unassigned In Progress issue is reported" {
	issue CLOUD-1 "In Progress" "" ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 in-progress-unassigned"* ]]
}

@test "an assigned In Progress issue is not" {
	issue CLOUD-1 "In Progress" someone ""
	check
	[ "$status" -eq 0 ]
}

@test "an In Review issue with no PR attachment is reported" {
	issue CLOUD-1 "In Review" someone ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 in-review-no-pr"* ]]
}

@test "an In Review issue with a linked PR is not" {
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	check
	[ "$status" -eq 0 ]
}

@test "a blockedBy cycle is reported with its members" {
	issue CLOUD-1 Todo "" "" CLOUD-2
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"blockedby-cycle"* ]]
	[[ "$output" == *"CLOUD-1"* && "$output" == *"CLOUD-2"* ]]
}

@test "a dangling blocker is reported" {
	issue CLOUD-1 Todo "" "" CLOUD-99
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 dangling-blocker (CLOUD-99)"* ]]
}

@test "the frontier is unblocked lint-passing Todo issues" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	issue CLOUD-3 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
	[[ "$output" == *"frontier CLOUD-3"* ]]
}

@test "a Todo issue blocked by unfinished work is off the frontier" {
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"frontier CLOUD-2"* ]]
}

@test "a blocker landed to In Review unblocks its dependents" {
	# Trunk-based: In Review means the code is on main, so a dependent can build.
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
}

# --- CLOUD-375: Todo is a column claim, and an unready queue entry falsifies it -
#
# The measured shape: three issues promoted Backlog -> Todo in one pass, two of
# them failing ready-lint, and this gate reporting `board coherent` over the
# closure that held them. Both were caught by a session running ready-lint by
# hand, which is discipline rather than a mechanism.

@test "a Todo issue with no Ready block is refused" {
	issue CLOUD-1 Todo "" ""
	# Overwrite its description with one carrying no Ready block at all.
	jq -c '.description = "just prose"' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 todo-not-ready"* ]]
	# Still off the frontier: the refusal is added to the exclusion, not swapped
	# for it — a caller reading the frontier must not be offered it either.
	[[ "$output" != *"frontier CLOUD-1"* ]]
}

@test "a Todo issue whose Ready block satisfies the clauses is not" {
	# ANTI-VACUITY, and the load-bearing half: a rule that fired on every Todo
	# issue would pass the deny case above while making the gate unusable.
	issue CLOUD-1 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-1"* ]]
	[[ "$output" != *"todo-not-ready"* ]]
}

@test "a Backlog issue with no Ready block is not refused" {
	# Backlog makes no claim, so there is nothing to falsify — the non-goal
	# asserted rather than assumed. A gate failing every ungroomed issue anywhere
	# in a piped closure would stop being piped.
	issue CLOUD-1 Backlog "" ""
	jq -c '.description = "just prose"' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-not-ready"* ]]
	[[ "$output" == *"board coherent"* ]]
}

@test "wip counts In Progress only" {
	issue CLOUD-1 "In Progress" a ""
	issue CLOUD-2 "In Review" b "https://github.com/o/r/pull/1"
	issue CLOUD-3 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"wip 1"* ]]
}

@test "output ordering is byte-stable and numeric" {
	issue CLOUD-10 Todo "" ""
	issue CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 0 ]
	first=$(grep -n "frontier CLOUD-2$" <<<"$output" | cut -d: -f1)
	second=$(grep -n "frontier CLOUD-10$" <<<"$output" | cut -d: -f1)
	[ "$first" -lt "$second" ]
}

@test "an array input works the same as a stream" {
	issue CLOUD-1 Todo "" ""
	jq -sc . "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
}

@test "unparseable stdin exits 2, not 1" {
	echo "not json" >"$BOARD"
	check
	[ "$status" -eq 2 ]
}

# --- CLOUD-251: an exclusion is attributable, and "could not look" is exit 2 ---
#
# The regression these pin: `|| continue` collapsed ready-lint's exit 1 and exit
# 2 into one silent absence, so "this is not Ready" and "you did not pipe me
# enough to judge it" were byte-identical, and a set whose relations the caller
# projected away was reported an acyclic, non-dangling board.

@test "an unjudgeable payload and a failing Ready block do not produce the same output" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	cp "$BOARD" "$BATS_TEST_TMPDIR/base.json"
	# One run with CLOUD-2's description key absent…
	jq -c 'if .id == "CLOUD-2" then del(.description) else . end' "$BATS_TEST_TMPDIR/base.json" >"$BOARD"
	unreadable=$(bash -c "'$CHECK' <'$BOARD' 2>&1" || true)
	# …and one where the same issue's Ready block genuinely fails.
	jq -c 'if .id == "CLOUD-2" then .description = "just prose" else . end' "$BATS_TEST_TMPDIR/base.json" >"$BOARD"
	failing=$(bash -c "'$CHECK' <'$BOARD' 2>&1" || true)
	[ "$unreadable" != "$failing" ]
	# Both still exclude it: what differs is the reason, not the frontier.
	[[ "$unreadable" != *"frontier CLOUD-2"* ]]
	[[ "$failing" != *"frontier CLOUD-2"* ]]
}

@test "a payload ready-lint cannot read is reported and exits 2" {
	issue CLOUD-1 Todo "" ""
	drop_key description
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-1 excluded (unjudgeable-ready-block)"* ]]
	[[ "$output" != *"board coherent"* ]]
	# "I could not read what you piped" is never collapsed into CLOUD-375's
	# violation: exit 2 asks for a re-fetch, exit 1 asks for the board to be fixed,
	# and answering the second over an unread payload sends the caller to the wrong
	# repair.
	[[ "$output" != *"todo-not-ready"* ]]
}

@test "a genuinely failing Ready block is attributed and refused" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 todo-not-ready"* ]]
	# ready-lint's own rule id, forwarded rather than re-derived — and still
	# pointer-only, so the body it judged never reaches the log.
	[[ "$output" == *"CLOUD-1:0 no-ready-block"* ]]
	[[ "$output" != *"$secret"* ]]
	# Its ::error:: summary is still dropped: one verdict gets one summary, and
	# this gate prints its own violation count.
	[[ "$output" != *"not Ready"* ]]
}

@test "a Todo issue held off the frontier by a blocker says which one" {
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 excluded (blocked-by CLOUD-1)"* ]]
}

@test "a set carrying no blockedBy data claims nothing about the graph" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-blockedby (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"board coherent"* ]]
}

@test "the missing-blockedBy report is keyed to the set, not to each issue" {
	# released's refusal_for greps this stderr for `^<id> <rule>`, so a per-id
	# line would turn every In Review issue in a relations-free sweep into a
	# REFUSED. The property is of the piped set, exactly like dangling-blocker.
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-blockedby (CLOUD-1)"* ]]
	[[ "$output" != *"CLOUD-1 unjudgeable"* ]]
}

@test "an explicit empty blockedBy is data, not an unjudgeable payload" {
	issue CLOUD-1 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"unjudgeable"* ]]
}

@test "a payload it could not read outranks a board it could" {
	issue CLOUD-1 "In Progress" "" ""
	issue CLOUD-2 Todo "" ""
	jq -c 'if .id == "CLOUD-2" then del(.description) else . end' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	# Both report sets print; the code says "re-fetch", not "fix your board".
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-1 in-progress-unassigned"* ]]
	[[ "$output" == *"CLOUD-2 excluded (unjudgeable-ready-block)"* ]]
}

@test "a judgeable, passing board emits no exclusion and no unjudgeable report" {
	# Anti-vacuity: the new reports must not decay into ones that always fire.
	# A real edge, so the graph claims are judged rather than absent.
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"excluded"* ]]
	[[ "$output" != *"unjudgeable"* ]]
	[[ "$output" == *"board coherent"* ]]
}

@test "a coherent set's stdout bytes are unchanged" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	check_out
	[ "$status" -eq 0 ]
	[ "$output" = "wip 0
frontier CLOUD-2
graph-check: board coherent (2 issues)" ]
}

@test "violations are pointer-only — no issue prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 "In Progress" "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}

# --- CLOUD-234: a status gloss is not a second authority for the board -------
#
# The measured shape: CLOUD-8's child inventory said "CLOUD-87 — **In Progress**
# (PR #157)" two seconds after CLOUD-87 completed and its PR merged. Every such
# block passed ready-lint at exit 0, because nothing checked a column word.

@test "a body claiming a column the board contradicts is reported" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 "Children:
* CLOUD-2 — **In Progress** (PR #157)"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"* ]]
}

@test "the same claim, agreeing with the board, is clean" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-2 — **Done**"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "a mention asserting no column is not a claim" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "Splits the representation CLOUD-2 introduced; see it for the rationale."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "Linear's stored mention markup is caught identically to the rendered form" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 '* <issue id="x" href="https://linear.app/i/CLOUD-2">CLOUD-2</issue> — **In Progress**'
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"* ]]
}

@test "a claim about an id outside the piped set is unjudgeable, never guessed" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-99 — **Done**"
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unjudgeable (CLOUD-1 claims CLOUD-99, not in the piped set)"* ]]
	# Keyed to the SET, not to the claiming issue: released's refusal_for greps
	# this stderr for `^<id> <rule>`, and which closure was piped is the caller's
	# choice, not that issue's dishonesty.
	[[ "$output" != *"CLOUD-1 status-claim-unjudgeable"* ]]
}

@test "a quoted or backticked citation of a claim is not a claim" {
	# Naming a claim is not making one — deferral-check's discipline, and the
	# reason this gate does not fail the very issue that ships it.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 'The inventory said "CLOUD-2 — **In Progress** (PR #157)" after it merged,
and the same defect in a span reads `CLOUD-2 — In Progress` too.'
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "narration about an issue is not a claim about its column" {
	# MEASURED, and the reason the connective is an allowlist. Over this repo's
	# own prose a length-bounded span with a `was|were` blocklist fired three
	# times, all wrong — these are two of them, and the blocklist that would fix
	# them has no end: went, sat, showed, landed.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	issue CLOUD-3 Done "" ""
	issue CLOUD-4 "In Progress" someone ""
	describe CLOUD-1 "CLOUD-2 went In Progress at 04:29 and CLOUD-3 still read In Progress.
CLOUD-2 was Done when this was written, then reopened."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "a gloss with no verb at all is a claim, in every shape the corpus uses" {
	# The complement of the row above: punctuation, emphasis, a table cell, or a
	# present-tense connective. Each must still be caught.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 Done "" ""
	issue CLOUD-4 Done "" ""
	issue CLOUD-5 "In Progress" someone ""
	describe CLOUD-1 "| CLOUD-2 | In Progress |
CLOUD-3 is In Progress
CLOUD-4 (now In Progress)"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 claimed In Progress, board says Done"* ]]
	[[ "$output" == *"CLOUD-3 claimed In Progress, board says Done"* ]]
	[[ "$output" == *"CLOUD-4 claimed In Progress, board says Done"* ]]
}

@test "a set with no descriptions cannot be scanned for claims, and says so" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	drop_key description
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-description (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"board coherent"* ]]
}

# CLOUD-526's accept row for this gate. The row above is the refusal half — a
# field this gate decides on is absent, so it says which and exits 2. This is the
# other half: a payload carrying ONLY the declared field set is accepted, with no
# unjudgeable report and no violation. Together they pin the contract from both
# sides, which is what stops the set drifting wider by accident.
#
# Unlike its three siblings, this gate genuinely reads the body — the §8 claim
# scan and the Ready-block delegation both consume it — so `description` is IN
# the set here. That asymmetry is the point of declaring the set per gate rather
# than once for all four.
@test "a set carrying only the declared field set is accepted" {
	jq -nc --arg ready "$READY" '{
		id: "CLOUD-1", status: "Todo",
		attachments: [], relations: {blockedBy: []},
		description: ("**Why**\nx.\n\n" + $ready),
		projectMilestone: {id: "m-1", name: "Phase 3"}
	}' >"$BOARD"
	jq -nc '{
		id: "CLOUD-2", status: "In Progress", assigneeId: "someone",
		attachments: [], relations: {blockedBy: []},
		description: "nothing to claim here"
	}' >>"$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"board coherent"* ]]
	[[ "$output" != *"unjudgeable"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
}

@test "a status claim report is pointer-only — no surrounding prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 "$secret: CLOUD-2 — **In Progress**"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"status-claim-disagrees"* ]]
	[[ "$output" != *"$secret"* ]]
}

@test "a column no piped issue occupies is not in the vocabulary" {
	# Stated rather than worked around. §1 forbids a second copy of the status
	# list, so the vocabulary is whatever the closure spells — the same way the
	# frontier is already relative to what was piped.
	#
	# CLOUD-838 gave the GLOSS form's silence a sibling that is not silent: the
	# same unspellable column, asserted with a present-tense connective, is
	# refused at exit 2 by the rows below. This shape stays exit 0 deliberately —
	# with no vocabulary to lean on, `— **In Review**` and `— **Batten**` are the
	# same bytes, and telling them apart needs the second authority §1 forbids.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-2 — **In Review**"
	check
	[ "$status" -eq 0 ]
}

# --- CLOUD-838: the alphabet's own anti-vacuity arm ---------------------------
#
# The scan's vocabulary is the piped set's OCCUPIED statuses, so a claim naming
# any other column never matched and the row passed silently — and a row that
# LEFT a column is exactly the row whose old column nothing in the set occupies.
# The predicate was weakest where it was most needed.

@test "a claim naming a column no piped issue occupies is refused, not ignored" {
	# Red before the arm: silent, exit 0.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"* ]]
	# Keyed to the SET, like status-claim-unjudgeable: which closure was piped is
	# the caller's choice, not this issue's dishonesty.
	[[ "$output" != *"CLOUD-1 status-claim-unscannable"* ]]
}

@test "the same claim, over a set that DOES occupy the column, is judged as before" {
	# The vocabulary can spell it now, so the existing exit-1 rule decides and the
	# new arm must stand down — one claim, one rule id, never both.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 Canceled "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement."
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed Canceled, board says Done)"* ]]
	[[ "$output" != *"status-claim-unscannable"* ]]
}

@test "a body carrying a stale claim AND its own correction reports the stale one" {
	# CLOUD-743's real shape, measured 2026-08-21 and the case the whole row
	# exists for. The correction is in the vocabulary (`Todo` is occupied), so the
	# gate matched it, compared it against the board, and passed — satisfied by
	# the accurate half of a body whose other half was false.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement.

Note also that CLOUD-2 is Todo, not Canceled."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"* ]]
	# The correction agrees with the board, so nothing disagrees — which is
	# precisely why the row above alone does not pin this.
	[[ "$output" != *"status-claim-disagrees"* ]]
}

@test "ordinary prose is not a claim, however capitalized" {
	# The bound on false triggers, and both halves of it. A capitalized word with
	# no connective is a mention; a connective with no capital is narration.
	# Measured over this repo's whole tracked tree: the claim shape occurs six
	# times and every one is a real column claim.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 Batten's engine, per the note above.
CLOUD-2 is the durable artifact this campaign rests on.
Splits the representation CLOUD-2 introduced; see Regorus for the rationale."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "an unscannable report is pointer-only — no surrounding prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "$secret: CLOUD-2 is now Canceled."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"status-claim-unscannable"* ]]
	[[ "$output" != *"$secret"* ]]
}

@test "a multi-word column is named whole, never its first word" {
	# `In` points at nothing a reader can act on. The span is capitalized WORDS,
	# because the columns it has to name are multi-word.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now In Review."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"claims CLOUD-2 is In Review"* ]]
}

@test "ANTI-VACUITY: a set with no status claims anywhere still exits 0" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
	[[ "$output" == *"board coherent"* ]]
}

# --- the board-move receipt (CLOUD-512) --------------------------------------

@test "a coherent board records which ids it judged" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 "In Review" "" "https://github.com/o/r/pull/1"
	check
	[ "$status" -eq 0 ]
	[ -f "$RECEIPT" ]
	# The ids are the point: a bare "graph-check ran" receipt is satisfied by
	# judging one clean issue and then sweeping fifteen.
	[[ "$(cat "$RECEIPT")" == *"CLOUD-1"* ]]
	[[ "$(cat "$RECEIPT")" == *"CLOUD-2"* ]]
	# Field 1 is the epoch the guard bounds; a non-numeric one makes it deny.
	[[ "$(awk '{print $1}' "$RECEIPT")" =~ ^[0-9]+$ ]]
}

@test "a board signalling falsely records nothing" {
	# In Review with no PR attachment — the CLOUD-480 shape. A refusal that still
	# minted would authorise the very move it just refused.
	issue CLOUD-3 "In Review" "" ""
	check
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPT" ]
}

@test "a board it could not read records nothing" {
	issue CLOUD-4 Done "" ""
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[ ! -f "$RECEIPT" ]
}

@test "runs accumulate rather than overwrite, so an earlier closure stays judged" {
	issue CLOUD-5 Done "" ""
	check
	[ "$status" -eq 0 ]
	: >"$BOARD"
	issue CLOUD-6 Done "" ""
	check
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$RECEIPT")" -eq 2 ]
	[[ "$(cat "$RECEIPT")" == *"CLOUD-5"* ]]
}

@test "the receipt is pointer-only — ids and an epoch, never issue prose" {
	issue CLOUD-7 Done "" ""
	check
	[[ "$(cat "$RECEIPT")" != *"Source of truth"* ]]
	[[ "$(cat "$RECEIPT")" != *"Refinement"* ]]
}

# A receipt that cannot be written must not turn a coherent board into a failing
# one: this gate's verdict is about the board, never about the store.
@test "an unwritable receipt store does not change the verdict" {
	issue CLOUD-8 Done "" ""
	mkdir -p "$REPO/.git/batten-receipts"
	chmod 500 "$REPO/.git/batten-receipts"
	check
	chmod 700 "$REPO/.git/batten-receipts"
	[ "$status" -eq 0 ]
}

# --- todo-unmilestoned (CLOUD-695) -------------------------------------------
#
# Todo is the ready queue, so sitting in it claims the work is pullable — and
# pullable work has to say which phase it advances. Nothing asked for ~340
# issues. These four rows are the clause and its one real hazard: Linear OMITS
# `projectMilestone` when it is null, so per-issue the field's absence cannot be
# told from a caller who projected it away, and the discriminator is the set.
#
# Fixtures, never the live board: the sweep this clause exists to make permanent
# will clean the live board, and a case reading it would go green for the wrong
# reason and could never fail again.

@test "a Todo issue carrying a milestone is clean, and still reaches the frontier" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-unmilestoned"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
}

@test "a Todo issue with no milestone, in a set where others carry one, is refused" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 todo-unmilestoned"* ]]
	# The judgeable one is not swept up with it, and the clause must not change
	# which issues are pullable.
	[[ "$output" != *"CLOUD-1 todo-unmilestoned"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
	# Pointer-only: the id and the rule, never the body the fixture carries.
	[[ "$output" != *"**Why**"* ]]
}

@test "a set with the field absent everywhere is unjudgeable, not a wall of violations" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	issue CLOUD-3 Done "" ""
	drop_key projectMilestone
	check
	# 2, not 1. Reporting these as violations is the CLOUD-679 shape — a finding
	# where the gate cannot look — and it would fire on every caller who projected
	# the field away.
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-milestone (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"todo-unmilestoned"* ]]
	# Only the Todo ids: a Done issue carries no milestone claim to judge.
	[[ "$output" != *"CLOUD-3"* ]]
}

@test "a Backlog issue with no milestone is clean — filing stays free" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 Backlog "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-unmilestoned"* ]]
	[[ "$output" != *"unjudgeable-milestone"* ]]
}
