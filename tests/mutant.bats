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

@test "A FILTER THAT SELECTS THE WHOLE SUITE names no case, like one that selects none" {
	# CLOUD-480, and it is `names-no-case` from the other side. A row carrying a
	# `|` inside its sed script is split into the wrong fields, and the filter it
	# ends up with can have an EMPTY leading alternation branch — which matches
	# everything. Measured on `mutant-census`'s own row: all 14 cases ran, the row
	# reported caught, and the case it named was never the reason.
	toy_gate
	toy_suite
	# An empty leading branch, which is what the mis-split produced.
	declare_mutant 'wide|s/^LIMIT=10$/LIMIT=1000/||over the limit is refused'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"filter-names-every-case"* ]]
	# It must not be reported as caught: the mutation IS caught by one of the two
	# cases, so without this term the row passes and the vacuity is invisible.
	[[ "$output" != *"every one caught"* ]]
}

@test "a filter selecting one case of a single-case suite is not read as too wide" {
	# The guard on the case above. A suite with one case cannot distinguish "names
	# that case" from "names all of them", so the term would refuse every honest
	# row in a one-case suite — the false positive that gets a gate switched off.
	toy_gate
	cat >"$REPO/tests/toy.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "over the limit is refused" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 99
			[ "$status" -eq 1 ]
		}
	EOF
	declare_mutant 'narrow|s/^LIMIT=10$/LIMIT=1000/|over the limit is refused'
	commit
	run_mutant
	[ "$status" -eq 0 ]
	[[ "$output" == *"every one caught"* ]]
}

@test "THE TREE IS RESTORED BETWEEN ROWS, so a gate is judged against a pristine sibling" {
	# CLOUD-480. The per-row `cp` restores the row's OWN subject; nothing restored
	# the last row's, so the throwaway tree accumulated corruption and a gate that
	# composes over a sibling was judged against the sibling's mutant. Measured:
	# `board-write-record`'s `overlap-frozen-at-write-time` is caught when its gate
	# is swept alone and SURVIVES in a full sweep, because `board-diff-overlap`'s
	# last row leaves that sibling pinned in the very mode the mutation was meant to
	# distinguish. A survivor that depends on sweep ORDER is worse than a missed
	# one: it reports a finding about the suite that changes with the set.
	printf '#!/usr/bin/env bash\necho strict\n' >"$REPO/mise-tasks/sibling.sh"
	chmod +x "$REPO/mise-tasks/sibling.sh"
	sed -i '2i #MUTANT sibling-goes-loose|s/^echo strict$/echo loose/|the sibling answers strict' \
		"$REPO/mise-tasks/sibling.sh"
	# TAB-indented heredocs throughout, so no fixture line begins with `@test `.
	cat >"$REPO/tests/sibling.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "the sibling answers strict" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/sibling.sh"
			[ "$output" = strict ]
		}
	EOF

	# The composer's verdict is a function of its sibling's answer, which is the
	# shape the restore has to protect: corrupt the sibling and this gate stops
	# refusing, so its own case is red before its own mutation is applied.
	cat >"$REPO/mise-tasks/composer.sh" <<-'EOF'
		#!/usr/bin/env bash
		mode=$("$(dirname -- "${BASH_SOURCE[0]}")/sibling.sh")
		[ "$mode" = strict ] || exit 0
		exit 1
	EOF
	chmod +x "$REPO/mise-tasks/composer.sh"
	sed -i '2i #MUTANT composer-never-refuses|s/^exit 1$/exit 0/|the composer refuses under a strict sibling' \
		"$REPO/mise-tasks/composer.sh"
	cat >"$REPO/tests/composer.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "the composer refuses under a strict sibling" {
			run "$BATS_TEST_DIRNAME/../mise-tasks/composer.sh"
			[ "$status" -eq 1 ]
		}
	EOF
	commit
	cd "$REPO" && MUTANT_GATES=sibling,composer run "$MUTANT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every one caught"* ]]
}

@test "A ROW THAT MUTATES ITS OWN DECLARATION is refused, not reported as a survivor" {
	# CLOUD-480. A row's pattern is a string that must also appear on the
	# declaration line, so a pattern spelled literally matches its own row: `cmp`
	# sees a change, the gate's behaviour is untouched, and the mutation survives
	# every run while reading as enforced coverage. `board-write-record`'s
	# `overlap-frozen-at-write-time` had done that for its whole life, and the
	# inertness term cannot see it — the file really did change.
	toy_gate
	toy_suite
	# The pattern matches nothing in the gate's code and everything in the row
	# itself, which is the shape a literal spelling produces by accident.
	declare_mutant 'self|s/MUTANT self/MUTANT other/|over the limit is refused'
	commit
	run_mutant
	[ "$status" -eq 1 ]
	[[ "$output" == *"self-mutating-row"* ]]
	[[ "$output" != *"SURVIVED"* ]]
}

@test "THE COPY IS A REPOSITORY, so a suite that resolves its own root answers about it" {
	# CLOUD-480. `git ls-files | tar` carries tracked bytes and no `.git`, so a
	# gate resolving its root with `git rev-parse --show-toplevel` answered about
	# whatever repository enclosed $TMPDIR, or about none — and the case came back
	# red for a reason unrelated to the mutation. This task then reported
	# `case-already-red`, naming the SUITE for a defect in the harness. Measured
	# on the first full sweep over 62 declarations: `hooks-wiring-check`'s
	# acceptance case, green in the tree and green in a git-initialised copy, red
	# in a copy without one.
	toy_gate
	# TAB-indented so no fixture line begins with `@test ` — same reason
	# `toy_suite` is, and the count gate in [tasks."test:bats"] is why.
	cat >"$REPO/tests/toy.bats" <<-'EOF'
		#!/usr/bin/env bats
		@test "over the limit is refused, from a root the suite resolves itself" {
			root=$(git rev-parse --show-toplevel)
			run "$root/mise-tasks/toy.sh" 99
			[ "$status" -eq 1 ]
		}
	EOF
	declare_mutant 'limit-removed|s/^LIMIT=10$/LIMIT=1000/|resolves itself'
	commit
	run_mutant
	[ "$status" -eq 0 ]
	[[ "$output" != *"case-already-red"* ]]
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
