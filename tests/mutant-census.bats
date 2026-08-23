#!/usr/bin/env bats
# subject: mise-tasks/mutant-census.sh
# The sensor on `$MUTANT_GATES` (CLOUD-480). `mutant` holds a gate IN the set to a
# declaration; nothing held the SET to the tree, so fifty-eight gates sat outside
# it and six of those carried `#MUTANT` rows no run had ever applied.
#
# Every case builds a throwaway repository, because the subject is the CENSUS and
# not this tree's coverage: a suite reading the live set would answer differently
# whenever somebody added a gate, which is the opposite of a decision table. The
# one exception is the last case, which is deliberately the live tree — it is what
# makes the fixtures above evidence about this repository.

setup() {
	CENSUS="$BATS_TEST_DIRNAME/../mise-tasks/mutant-census.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/mise-tasks" "$REPO/policy"
	git -C "$REPO" init -q
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
}

# A task file whose only load-bearing content is the description the classifier
# reads. `$1` name, `$2` description.
task() {
	printf '#!/usr/bin/env bash\n#MISE description="%s"\nexit 0\n' "$2" >"$REPO/mise-tasks/$1.sh"
	chmod +x "$REPO/mise-tasks/$1.sh"
}

exempt() { # $1 task, $2 row body
	sed -i "3i #MUTANT-EXEMPT $2" "$REPO/mise-tasks/$1.sh"
}

census() { # $1 = the set
	cd "$REPO" && MUTANT_GATES="$1" run "$CENSUS"
}

@test "a gate named in the set is a closed census" {
	task alpha-check "Gate: alpha refuses"
	census alpha-check
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 gate(s)"* ]]
}

@test "THE DEFECT: a gate the set omits is uncovered, and named" {
	task alpha-check "Gate: alpha refuses"
	task beta-check "Gate: beta refuses"
	census alpha-check
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/beta-check.sh uncovered"* ]]
	[[ "$output" != *"alpha-check.sh uncovered"* ]]
}

@test "a task that does not describe itself as a gate owes no mutation" {
	task alpha-check "Gate: alpha refuses"
	task measure "Measure: how long something took"
	task launcher "Effect: hold a lease"
	census alpha-check
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 gate(s)"* ]]
}

@test "a hook body is a gate too — it decides by emitting a deny" {
	task alpha-check "Gate: alpha refuses"
	task some-guard "PreToolUse hook body: deny a call nobody authorised"
	census alpha-check
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/some-guard.sh uncovered"* ]]
}

@test "a policy module is censused unconditionally, so a migration cannot shrink the set" {
	task alpha-check "Gate: alpha refuses"
	printf 'package batten\n' >"$REPO/policy/some-rule.rego"
	census alpha-check
	[ "$status" -eq 1 ]
	[[ "$output" == *"policy/some-rule.rego uncovered"* ]]
}

@test "a filed exemption is a closed census, not a gap" {
	task alpha-check "Gate: alpha refuses"
	task beta-check "Gate: beta refuses"
	exempt alpha-check "CLOUD-931|its suite runs no arm that can go red"
	census beta-check
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 gate(s)"* ]]
}

@test "an exemption naming no issue is unfiled — the whole difference from a TODO" {
	task alpha-check "Gate: alpha refuses"
	exempt alpha-check "later|its suite runs no arm that can go red"
	census alpha-check-nope
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/alpha-check.sh exempt-unfiled"* ]]
}

@test "an exemption with no reason is unfiled as well" {
	task alpha-check "Gate: alpha refuses"
	exempt alpha-check "CLOUD-931"
	census alpha-check-nope
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/alpha-check.sh exempt-unfiled"* ]]
}

@test "declared AND exempt is refused — the reason would be a dead letter" {
	task alpha-check "Gate: alpha refuses"
	exempt alpha-check "CLOUD-931|its suite runs no arm that can go red"
	census alpha-check
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/alpha-check.sh declared-and-exempt"* ]]
}

@test "THE REVERSE DIRECTION: a name in the set resolving to no gate is refused" {
	task alpha-check "Gate: alpha refuses"
	census alpha-check,ghost-check
	[ "$status" -eq 1 ]
	[[ "$output" == *"ghost-check names-no-subject"* ]]
}

@test "an unset set is could-not-look, never a closed census" {
	task alpha-check "Gate: alpha refuses"
	cd "$REPO" && run env -u MUTANT_GATES "$CENSUS"
	[ "$status" -eq 2 ]
	[[ "$output" == *"MUTANT_GATES is unset"* ]]
}

@test "ANTI-VACUITY: a tree resolving no gate at all is exit 2, not perfect coverage" {
	census alpha-check
	[ "$status" -eq 2 ]
	[[ "$output" == *"no gate resolved"* ]]
}

@test "output is pointer-only — the exemption's reason never reaches the log" {
	task alpha-check "Gate: alpha refuses"
	exempt alpha-check "CLOUD-931|SECRETPROSE about why the suite cannot discriminate"
	census alpha-check
	[ "$status" -eq 1 ]
	[[ "$output" != *"SECRETPROSE"* ]]
}

@test "this repository's own census is closed — the gate on the real tree" {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run mise run mutant-census
	[ "$status" -eq 0 ]
}
