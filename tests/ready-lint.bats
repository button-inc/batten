#!/usr/bin/env bats
# ready-lint's decision table (CLOUD-179), driven by get_issue-shaped payloads.
#
# The cases that matter are the ones prose cannot fake: a blocker asserted in §8
# text with no matching `blockedBy` relation, and a §6 bump that disagrees with
# its own commit type. Everything else here exists to pin the deliberate
# non-behaviours — chiefly that an omitted clause is NOT a violation, because the
# Definition of Ready forbids restating clauses and the corpus's best issue
# (CLOUD-33) omits §4.

setup() {
	LINT="$BATS_TEST_DIRNAME/../mise-tasks/ready-lint"
}

# Writes a get_issue payload to $PAYLOAD: $1 description, rest are blockedBy ids.
payload() {
	local desc="$1"
	shift
	local rel="[]"
	if [ "$#" -gt 0 ]; then
		rel=$(printf '%s\n' "$@" | jq -R '{id: .}' | jq -sc .)
	fi
	PAYLOAD="$BATS_TEST_TMPDIR/payload.json"
	jq -nc --arg d "$desc" --argjson r "$rel" \
		'{id: "CLOUD-999", description: $d, relations: {blockedBy: $r}}' >"$PAYLOAD"
}

# Runs the lint over the payload just built.
lint() { run bash -c "'$LINT' <'$PAYLOAD'"; }

# A minimal well-formed block. Only the clauses under test are ever added.
block() {
	cat <<-EOF
		**Why**
		Something needs doing.

		**Refinement — Ready (a summary)**

		* **Source of truth (§1).** One authoritative artifact.
		$*
	EOF
}

@test "a well-formed block passes" {
	payload "$(block '* **Commit / bump (§6).** `ci` → **no bump**.')"
	lint
	[ "$status" -eq 0 ]
}

@test "omitted clauses are not a violation" {
	# The load-bearing non-behaviour: a body carrying only §1 is legal, because
	# the gate document says bodies carry specializations, not restatements.
	payload "$(block '')"
	lint
	[ "$status" -eq 0 ]
}

@test "a blocker cited in §8 with no relation is reported" {
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (the loader this validates).')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"blocker-cited-without-relation (CLOUD-29)"* ]]
}

@test "the same citation passes when the relation actually exists" {
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (the loader this validates).')
	payload "$d" CLOUD-29
	lint
	[ "$status" -eq 0 ]
}

@test "a blocker noted as closed needs no relation" {
	# Linear drops the relation once a dependency resolves, so demanding one here
	# would fail every correctly-refined issue whose blocker has landed.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-21 (closed).')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "§8 None is an explicit, valid answer" {
	local d
	d=$(block '* **Blockers (§8).** None.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a bump disagreeing with its commit type is reported" {
	local d
	d=$(block '* **Commit / bump (§6).** `feat` → **patch**.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"bump-disagrees-with-type"* ]]
}

@test "feat to minor agrees" {
	local d
	d=$(block '* **Commit / bump (§6).** `feat` → **minor**.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a §6 clause naming no commit type is reported" {
	local d
	d=$(block '* **Commit / bump (§6).** To be decided.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"commit-type-missing"* ]]
}

@test "an open-questions marker blocks Ready" {
	# The questions-are-artifacts protocol is only real because of this gate:
	# without it a question can be written and the issue promoted anyway.
	local d
	d=$(block '**Open questions blocking Ready:**
	1. Where does it live?')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"open-questions-block-ready"* ]]
}

@test "the retired (clause N) dialect is reported, not silently accepted" {
	local d
	d=$(block '* **Effect (clause 3).** read.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"non-canonical-clause-notation"* ]]
}

@test "an issue with no Ready block at all is reported" {
	payload 'Just a description.'
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-ready-block"* ]]
}

@test "unparseable stdin exits 2, not 1" {
	# A caller piping the wrong thing must not look like a failing issue.
	echo 'not json' >"$BATS_TEST_TMPDIR/bad"
	PAYLOAD="$BATS_TEST_TMPDIR/bad"
	lint
	[ "$status" -eq 2 ]
}

@test "output is pointer-only — no issue prose echoed" {
	# Non-negotiable rule 4: issue bodies can carry customer detail, and a lint
	# that echoed them would leak through CI logs.
	local secret='ACME Corp renewal blocker'
	local d
	d=$(block "* **Blockers (§8).** \`blockedBy\` CLOUD-29 ($secret).")
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}
