#!/usr/bin/env bats
# subject: mise-tasks/mutant.sh
# The gate on the gates (CLOUD-418): a declared mutation must make a NAMED case in
# the gate's own suite go red, and a mutation nothing catches is the defect.
#
# Every case builds a throwaway repository with one toy gate and one toy suite,
# because the subject here is the HARNESS, not any real gate's coverage. Running
# it against the live `$MUTANT_GATES` would make this file's verdict a function of
# whichever gate someone edited last, which is the opposite of a decision table.
#
# `git` and `bats` are real. The repo is local and instant, and stubbing either
# would test the stub — the same reasoning `tests/ci-lease-precondition.bats`
# records for its own throwaway repo.

setup() {
	MUTANT="$BATS_TEST_DIRNAME/../mise-tasks/mutant.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/mise-tasks" "$REPO/tests"
	# The runner, borrowed rather than re-vendored: it is the same binary either
	# way, and a second submodule checkout per case would dominate the runtime.
	ln -s "$BATS_TEST_DIRNAME/bats" "$REPO/tests/bats"
	git -C "$REPO" init -q
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	export MUTANT_GATES=toy
}

# A toy gate with one real decision, and a suite that asserts it. `$1` overrides
# the threshold so a case can make the gate wrong on purpose.
toy_gate() {
	cat >"$REPO/mise-tasks/toy.sh" <<EOF
#!/usr/bin/env bash
set -uo pipefail
LIMIT=${1:-10}
[ "\${1:-0}" -le "\$LIMIT" ] || exit 1
exit 0
EOF
	chmod +x "$REPO/mise-tasks/toy.sh"
}

toy_suite() {
	# `<<-` and TAB-indented, so no fixture line begins with `@test `. The count
	# gate in `[tasks."test:bats"]` derives its expectation from
	# `git grep -c '^@test '`, which cannot tell a case from a case this file
	# WRITES — three phantom counts here made the suite report 1333 of 1337 and
	# fail a gate whose whole job is noticing a suite that ran fewer tests.
	cat >"$REPO/tests/toy.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "over the limit is refused" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 99
			[ "$status" -eq 1 ]
		}
		@test "under the limit passes" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 1
			[ "$status" -eq 0 ]
		}
	EOF
}

# `<slug>|<sed script>|<case name>`, inserted where a real gate carries it.
declare_mutant() {
	sed -i "2i #MUTANT $1" "$REPO/mise-tasks/toy.sh"
}

commit() {
	git -C "$REPO" add -A
	git -C "$REPO" commit -qm t
}

run_mutant() { cd "$REPO" && run "$MUTANT"; }

@test "a mutation its suite catches is a pass" {
	toy_gate
	toy_suite
	declare_mutant 'limit-removed|s/^LIMIT=10$/LIMIT=1000/|over the limit is refused'
	commit
	run_mutant
	[ "$status" -eq 0 ]
	[[ "$output" == *"every one caught"* ]]
}

@test "THE DEFECT: a mutation the suite does NOT catch fails" {
	# The whole point. A test that passes on both the fixed and the broken code
	# satisfies every other rule in this repository, and four separate times that
	# was discovered only after the fact — once live, when someone chose to restore
	# a bug and found the green test stayed green.
	toy_gate
	toy_suite
	# Changing a value no case exercises: the gate is corrupted, both cases still
	# pass, and that is exactly what must be reported.
	declare_mutant 'unwatched|s/^set -uo pipefail$/set -uo pipefail # unwatched/|under the limit passes'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"SURVIVED"* ]]
}

@test "ANTI-VACUITY: a listed gate with NO declaration fails, rather than being skipped" {
	# Without this the task reports success over a set it never touched, which is
	# the "reads as coverage" defect CLOUD-418 was filed about, reproduced by its
	# own remedy.
	toy_gate
	toy_suite
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-mutant-declared"* ]]
}

@test "ANTI-VACUITY: a filter naming no case is not a pass" {
	# A `--filter` matching nothing exits 0 with no cases run, which would read as
	# "caught" — the vacuous pass this task exists to refuse, one level up. Hit for
	# real on the mechanism's first run, when a suite's new case was uncommitted.
	toy_gate
	toy_suite
	declare_mutant 'typo|s/^LIMIT=10$/LIMIT=1000/|no case is named this'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"names-no-case"* ]]
}

@test "ANTI-VACUITY: a mutation that changes nothing is not a pass" {
	# An inert script would otherwise be reported as caught or missed on the
	# strength of an unrelated case, which proves nothing about either.
	toy_gate
	toy_suite
	declare_mutant 'inert|s/^NOTHING_MATCHES_THIS$/x/|over the limit is refused'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"inert-mutation"* ]]
}

@test "an unset enforced set is fatal rather than an empty one" {
	# An empty set makes this a task that silently covers nothing — the same false
	# green as an empty $CI_REQUIRED_CHECKS, in a different currency.
	toy_gate
	toy_suite
	commit
	cd "$REPO" && run env -u MUTANT_GATES "$MUTANT"
	[ "$status" -eq 2 ]
	[[ "$output" == *"MUTANT_GATES is unset"* ]]
}

@test "a gate named with no suite is reported, not silently passed" {
	toy_gate
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-suite"* ]]
}

@test "POINTER, NEVER PAYLOAD: the report carries no line of the mutated source" {
	# Non-negotiable rule 4. The gate, the mutant id and the case that failed to
	# notice — never a diff.
	toy_gate
	toy_suite
	declare_mutant 'unwatched|s/^set -uo pipefail$/set -uo pipefail # SECRETMARKER/|under the limit passes'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" != *"SECRETMARKER"* ]]
}

@test "the tracked file is never mutated in place" {
	# Not fastidiousness: mutating in place made a corrupted commit reachable from
	# any concurrent `git add -A`, and staged a mutant into a pushed commit on
	# 2026-08-12 (recorded on CLOUD-418).
	toy_gate
	toy_suite
	declare_mutant 'limit-removed|s/^LIMIT=10$/LIMIT=1000/|over the limit is refused'
	commit
	before=$(git -C "$REPO" hash-object mise-tasks/toy.sh)
	run_mutant
	[ "$status" -eq 0 ]
	[ "$(git -C "$REPO" hash-object mise-tasks/toy.sh)" = "$before" ]
	[ -z "$(git -C "$REPO" status --porcelain)" ]
}

@test "an UNCOMMITTED case is still covered — the working tree is the subject" {
	# The moment this matters most is while a gate and its suite are being written.
	# A sweep reading `git archive HEAD` reported `names-no-case` over every case
	# not yet committed, which is a pass-shaped failure at exactly the wrong time.
	toy_gate
	toy_suite
	declare_mutant 'limit-removed|s/^LIMIT=10$/LIMIT=1000/|over the limit is refused'
	commit
	# Now break the gate further and rewrite the suite WITHOUT committing.
	cat >>"$REPO/tests/toy.bats" <<-'EOF'
		@test "an uncommitted case is exercised" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 50
			[ "$status" -eq 1 ]
		}
	EOF
	sed -i 's/^#MUTANT .*/#MUTANT fresh|s\/^LIMIT=10$\/LIMIT=1000\/|an uncommitted case is exercised/' "$REPO/mise-tasks/toy.sh"
	run_mutant
	[ "$status" -eq 0 ]
	[[ "$output" == *"every one caught"* ]]
}

@test "ANTI-VACUITY: a case that is red BEFORE the mutation is not evidence" {
	# The third evasion, and the one that hid two defects at once on this branch:
	# `checks-green`'s CLOUD-376 row asserted `[[ "$output" != *"red"* ]]` against
	# a message reading "requi-red check(s)", so it could never pass — and the
	# mutation aimed at it targeted an expression that could not change its
	# outcome. Red under mutation is only evidence if the row was green without
	# it, so a case already failing is reported rather than counted as caught.
	toy_gate
	cat >"$REPO/tests/toy.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "over the limit is refused" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 99
			[ "$status" -eq 99 ]
		}
	EOF
	declare_mutant 'limit-removed|s/^LIMIT=.*/LIMIT=999/|over the limit is refused'
	commit
	run env MUTANT_GATES=toy bash -c "cd '$REPO' && '$MUTANT'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"case-already-red"* ]]
	# And it is NOT reported as caught, which is the whole point.
	[[ "$output" != *"every one caught"* ]]
}
