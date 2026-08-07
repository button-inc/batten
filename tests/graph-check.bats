#!/usr/bin/env bats
# graph-check's decision table (CLOUD-175): the two board predicates from
# mem:workflow/board-states as exit codes, graph coherence, and the frontier as
# a by-product. Fixtures are get_issue-shaped payloads built with jq.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/graph-check"
	BOARD="$BATS_TEST_TMPDIR/board.json"
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

@test "violations are pointer-only — no issue prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 "In Progress" "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}
