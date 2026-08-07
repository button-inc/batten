#!/usr/bin/env bats
# Deferral claims held to the board, the same predicate §8 applies to blockers.
#
# An issue that says an obligation is someone else's — "deferred to CLOUD-N" —
# is asserting a hand-off. Without a relation the board does not know about it,
# and the obligation belongs to nobody. Prose is where obligations go to die;
# this makes the claim checkable.
#
# The hard half is NOT flagging the cross-references that make issues readable.
# Comparisons, provenance and "see also" mention ids without handing anything
# off, and a lint that punished them would push authors to stop cross-referencing.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ready-lint"
	PAYLOAD="$BATS_TEST_TMPDIR/issue.json"
}

# Build a get_issue payload: $1 = prose appended after a minimal Ready block,
# $2… = ids present as relations.
issue() {
	local body=$1
	shift
	local rels="[]"
	if [ "$#" -gt 0 ]; then
		rels=$(printf '%s\n' "$@" | jq -R '{id: .}' | jq -sc '.')
	fi
	jq -n --arg b "$body" --argjson r "$rels" '{
    id: "CLOUD-1", status: "Todo",
    relations: {blockedBy: [], relatedTo: $r},
    description: ("## Ready\n\nA thing.\n\n### Blockers (§8)\n\nNone.\n\n## Done\n\n" + $b)
  }' >"$PAYLOAD"
}

# --- claims are held to the board -------------------------------------------

@test "a deferral with no relation is reported" {
	issue "The wiring is deferred to CLOUD-61."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-cited-without-relation (CLOUD-61)"* ]]
}

@test "the same deferral with a relation passes" {
	issue "The wiring is deferred to CLOUD-61." CLOUD-61
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

@test "ownership phrasing is a hand-off too" {
	issue "That transition is owned by CLOUD-174."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 1 ]
}

@test "a deferral outside the Ready block still counts" {
	# Deferrals live in Done, Open questions and out-of-scope notes — exactly
	# where an obligation is most likely to be quietly abandoned.
	issue "## Open questions\n\nThe general migration belongs to CLOUD-14."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 1 ]
}

@test "Linear's stored mention markup is the same case as the rendered form" {
	issue 'Deferred to <issue id="x" href="y">CLOUD-61</issue>.'
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-61"* ]]
}

@test "any relation direction satisfies it — a deferral is not always a blocker" {
	# Demanding blockedBy specifically would push authors to declare false
	# dependencies to pass the lint.
	issue "Deferred to CLOUD-61." CLOUD-61
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

# --- mentions are not claims -------------------------------------------------

@test "a comparison is not a hand-off" {
	issue "This is the same failure shape as CLOUD-195."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

@test "provenance is not a hand-off" {
	issue "Split out of CLOUD-177, which is Done on its own scope."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

@test "a bare cross-reference is not a hand-off" {
	issue "See CLOUD-33 for the most refined example in the corpus."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

@test "an id far from the verb is not what was deferred" {
	# "CLOUD-9 blocks this, deferred to CLOUD-10" hands off CLOUD-10 only.
	issue "CLOUD-9 describes the shape. Deferred to CLOUD-10." CLOUD-10
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

@test "an issue cannot defer to itself" {
	issue "Deferred to CLOUD-1."
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 0 ]
}

# --- posture -----------------------------------------------------------------

@test "output is a pointer — a line number and a rule id, never the prose" {
	issue "The confidential wiring detail is deferred to CLOUD-61."
	run "$GATE" <"$PAYLOAD"
	[[ "$output" != *"confidential wiring detail"* ]]
	[[ "$output" == *"CLOUD-1:"* ]]
}

@test "a payload with no relations key is not a parse failure" {
	jq -n '{id: "CLOUD-1", status: "Todo",
    description: "## Ready\n\nA thing.\n\n## Done\n\nDeferred to CLOUD-61."}' >"$PAYLOAD"
	run "$GATE" <"$PAYLOAD"
	[ "$status" -eq 1 ]
	[[ "$output" == *"deferral-cited-without-relation"* ]]
}
