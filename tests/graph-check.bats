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
		--argjson att "$att" --argjson rel "$rel" '{
		id: $id, status: $st, attachments: $att,
		relations: {blockedBy: $rel},
		description: "**Why**\nx.\n\n**Refinement — Ready (t)**\n\n* **Source of truth (§1).** One artifact."
	} + (if $a == "" then {} else {assigneeId: $a} end)' >>"$BOARD"
}

check() { run bash -c "'$CHECK' <'$BOARD'"; }
# stdout alone, for the cases that pin the frontier's bytes rather than a report.
check_out() { run bash -c "'$CHECK' <'$BOARD' 2>/dev/null"; }

# Drop a key from every payload in the board — the projection a caller makes when
# it fetches without includeRelations, or assembles the set by hand.
drop_key() {
	jq -c "del(.$1)" "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
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

@test "a Todo issue failing ready-lint is off the frontier" {
	issue CLOUD-1 Todo "" ""
	# Overwrite its description with one carrying no Ready block at all.
	jq -c '.description = "just prose"' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"frontier CLOUD-1"* ]]
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
}

@test "a genuinely failing Ready block is attributed and leaves the exit code alone" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-1 excluded (not-ready)"* ]]
	# ready-lint's own rule id, forwarded rather than re-derived — and still
	# pointer-only, so the body it judged never reaches the log.
	[[ "$output" == *"CLOUD-1:0 no-ready-block"* ]]
	[[ "$output" != *"$secret"* ]]
	# Its ::error:: summary is dropped: an annotation at exit 0 is a false signal.
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
