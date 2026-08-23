#!/usr/bin/env bash
#MISE description="Gate: every declared gate has a mutation its own suite is PROVEN to catch (CLOUD-418)"
#
# THE OBLIGATION THIS REPOSITORY ACTUALLY HAD WAS "a rule ships with a runnable
# gate" — a gate that EXISTS. Nothing required evidence that it DISCRIMINATES, and
# a test which passes on both the fixed and the broken code satisfies every other
# rule here. That is this repo's most-repeated failure, four times over: `land`'s
# refusal branch was dead for months (CLOUD-235), `timeout-check`'s budgets were
# placeholders that could not fire (CLOUD-352), a shape rule whose `pattern` was a
# program could never match and read as coverage (CLOUD-401) — and then it
# happened live while building the landing lease. A concurrency test was written
# for a real race, was green, and PASSED ON THE BROKEN CODE when someone chose to
# restore the bug and re-run. It asserted nothing. The green suite before that
# check and the green suite after it were indistinguishable.
#
# So: a gate is covered when a stated one-line corruption of it makes a NAMED case
# in its own suite go RED. A pass under mutation is the defect.
#
# THE ENFORCED SET IS DATA, AND ITS GAPS ARE FILED (CLOUD-418, narrowed). The
# property needed is "coverage cannot be silently zero", and a visible list with
# filed gaps has that property. `$MUTANT_GATES` in mise.toml [env] names what is
# enforced; a gate IN it with no declaration FAILS here. Declaring all forty-odd
# gates at once would have put branch age — the thing that multiplies laps and CI
# runs — on the critical path of the change that reduces them.
#
# THE COMPLEMENT IS `mutant-census`'s, NOT THIS TASK'S (CLOUD-480). "A gate not in
# the set is a filed row rather than a silent exemption" was the seed's stated
# posture and nothing held the set to the tree, so fifty-eight gates sat outside
# it — six of them carrying `#MUTANT` rows no run had ever applied, which is a
# declaration reading as coverage, this task's own defect one level up. The census
# is the sensor on that, in the gate, and it is the reason this task can stay off
# the landing path: it proves the declarations DISCRIMINATE, at two filtered bats
# runs a row, where the census proves they EXIST, at one pass over the tree.
#
# NEVER MUTATE THE TRACKED FILE. That is not fastidiousness: mutating in place
# made a corrupted commit reachable from any concurrent `git add -A`, and staged a
# mutant into a pushed commit on 2026-08-12. Every run here builds a throwaway
# copy of the tracked tree and mutates THAT, which is also why no suite needs a
# bespoke `*_UNDER_TEST` indirection to be covered.
#
# OFF THE LANDING PATH, deliberately. This is a proof about the SUITE, not a
# property of the commit, so it belongs neither in `verify` nor in CI — the same
# split `lock-complete` and `lock-currency` were separated along. Run it when a
# gate or its suite changes.
#
# Output is pointer-only per non-negotiable rule 4: the gate, the mutant id and
# the case that failed to notice. Never a diff of the mutated source.
#
# Exit 0 every declared mutant was caught / 1 one was not / 2 could not look.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
# The restore is the fourth harness property with a row of its own: without it a
# gate composing over a sibling is judged against the sibling's mutant, and the
# survivor it reports changes with the sweep ORDER.
#MUTANT tree-not-restored-between-rows|s/^\t\trestore_tree$/\t\t:/|THE TREE IS RESTORED BETWEEN ROWS
#MUTANT survivor-passes|s/^\texit 1$/\texit 0/|a mutation the suite does NOT catch fails

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

fail_input() {
	echo "::error:: mutant: $*" >&2
	exit 2
}

gates="${MUTANT_GATES:-}"
[[ -n "$gates" ]] ||
	fail_input "MUTANT_GATES is unset — run this through \`mise run mutant\`, which is where the enforced set is declared. An empty set makes this a task that silently covers nothing, which is the defect it exists to refuse."

bats_bin="tests/bats/bin/bats"
[[ -x "$bats_bin" ]] ||
	fail_input "tests/bats is missing; run \`mise run doctor\`. A harness that cannot run a suite cannot prove one discriminates."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# THE WORKING TREE'S TRACKED FILES, not `git archive HEAD`. Tracked-only, so an
# untracked scratch file cannot change a verdict — but the WORKING copy, because
# the moment this matters most is while a gate and its suite are being written,
# and a sweep that could only see the last commit would report `names-no-case`
# over every case not yet committed. Measured on its own first run.
git ls-files -z | tar --null -T - -cf - | tar -x -C "$work" ||
	fail_input "could not stage the tracked tree"
# The submodule's contents are not in the archive; the runner is the same binary
# either way, so a symlink is honest here rather than a second checkout.
rm -rf "${work:?}/tests/bats"
ln -s "$(pwd)/tests/bats" "$work/tests/bats" || fail_input "could not provide the bats runner"

# THE COPY MUST BE A REPOSITORY, and this is a defect rather than a nicety
# (CLOUD-480). `git ls-files | tar` carries tracked bytes and no `.git`, so a
# suite whose gate resolves its root with `git rev-parse --show-toplevel` ran
# against whatever repository happened to enclose `$TMPDIR` — or none — and the
# case came back red for a reason that had nothing to do with the mutation.
# `mutant` then reported `case-already-red`, naming the SUITE for a defect in
# this harness, which is the wrong subject and the expensive kind of wrong: it
# reads as a finding about coverage. Measured on the first full sweep:
# `hooks-wiring-check`'s acceptance case, green in the tree and green in a
# git-initialised copy, red in a copy without one.
#
# Identity is passed per-command rather than written into a config, so a
# contributor with no global `user.email` gets the same throwaway commit as CI.
if ! {
	git -C "$work" init -q &&
		git -C "$work" add -A &&
		git -C "$work" -c user.email=mutant@localhost -c user.name=mutant commit -qm 'mutant: the tree under judgement'
}; then
	fail_input "could not make the staged tree a repository; a suite that resolves its own root would answer about the wrong one"
fi

failures=0
declared=0

# THE TREE IS RESTORED BETWEEN ROWS, and this is a defect the per-row `cp` below
# does not cover (CLOUD-480). That `cp` restores THIS row's subject; nothing
# restored the LAST row's, so the throwaway tree accumulated corruption and a gate
# that composes over a sibling was judged against the sibling's mutant. Measured:
# `board-write-record`'s `overlap-frozen-at-write-time` is caught when its gate is
# swept alone and SURVIVES in a full sweep, because `board-diff-overlap`'s last row
# leaves that sibling pinned in named-only mode — the exact state the mutation was
# supposed to distinguish. A survivor that depends on sweep ORDER is worse than a
# missed one: it reports a finding about the suite that changes with the set.
dirty=""
restore_tree() {
	[[ -n "$dirty" ]] || return 0
	cp "$dirty" "$work/$dirty" || fail_input "could not restore $dirty in the staged tree"
	dirty=""
}

# `#MUTANT <slug>|<sed script>|<case-name substring>` — beside the code it
# corrupts, for the reason `step-receipt`'s spec table lives in `step-receipt`: a
# declaration in a second file is a second authority that drifts.
for gate in ${gates//,/ }; do
	# A GATE IS NO LONGER ONLY A SHELL TASK (CLOUD-843). The retirement campaign
	# moves predicates out of `mise-tasks/` and into policy modules, and a
	# migration that could not declare a mutation would REDUCE the enforced set
	# while reporting the census going down — the exact false progress that
	# campaign exists to make visible. So the subject is resolved rather than
	# assumed: a shell task first, then the module of the same name. The suite is
	# `tests/<gate>.bats` either way, and a `#MUTANT` row is a `#` comment in both
	# languages, so nothing else about this task changes.
	#
	# The shell arm carries the extension and the set does not: `$MUTANT_GATES`
	# names TASKS, and a task name has none — `mise run land` resolves `land.sh`
	# because `Task::is_match` strips one (CLOUD-865). The `.rego` arm already
	# spelled its own extension for the same reason, so both arms now build the
	# filename rather than assuming the task name is one.
	src="mise-tasks/$gate.sh"
	[[ -f "$src" ]] || src="policy/$gate.rego"
	suite="tests/$gate.bats"
	[[ -f "$src" ]] || {
		echo "$gate no-such-gate"
		failures=$((failures + 1))
		continue
	}
	[[ -f "$suite" ]] || {
		echo "$gate no-suite ($suite)"
		failures=$((failures + 1))
		continue
	}

	rows="$(sed -n 's/^#MUTANT //p' "$src")"
	# THE ANTI-VACUITY TERM, AND IT IS THE WHOLE DESIGN. A listed gate with no
	# declaration is a failure, not a skip. Without this the task reports success
	# over a set it never touched — which is exactly the "reads as coverage"
	# defect CLOUD-418 was filed about, reproduced by its own remedy.
	[[ -n "$rows" ]] || {
		echo "$gate no-mutant-declared"
		failures=$((failures + 1))
		continue
	}

	while IFS= read -r row; do
		[[ -n "${row:-}" ]] || continue
		declared=$((declared + 1))
		# A ROW IS EXACTLY THREE FIELDS, CHECKED BEFORE IT IS SPLIT (CLOUD-480).
		# This is the root the other two evasions grow from: `read -r slug script
		# want` collapses every extra `|` into `want`, so a sed script containing
		# one is silently truncated AND its tail becomes part of the filter — an
		# ERE with an empty leading branch, which selects the whole suite. Both
		# halves then read as coverage. Measured: four rows in this tree carried 5
		# and 7 fields after a repair that left the old tail in place, and the
		# sweep called every one of them caught.
		#
		# Counted before splitting, because after the split the evidence is gone:
		# `want` holding a `|` is indistinguishable from a filter that meant to.
		row_fields=$(awk -F'|' '{print NF}' <<<"$row")
		if [[ "$row_fields" != 3 ]]; then
			echo "$gate/${row%%|*} malformed-row ($row_fields fields, want 3)"
			failures=$((failures + 1))
			continue
		fi
		IFS='|' read -r slug script want <<<"$row"
		# The previous row's subject first — it may be a DIFFERENT gate's file, and
		# this row's suite may compose over it.
		restore_tree
		cp "$src" "$work/$src" || fail_input "could not stage $src"

		# THE CASE MUST BE GREEN BEFORE IT IS MUTATED, and this is the third
		# evasion rather than a nicety. "Red under mutation" is only evidence if
		# the row was green without it: a case that CANNOT pass — an assertion
		# that never holds, a fixture that never builds — is red either way, and
		# every mutation aimed at it reads as caught. Measured on this branch:
		# `checks-green`'s CLOUD-376 row asserted `[[ "$output" != *"red"* ]]`
		# against a message that says "requi-red check(s)", so it was permanently
		# red, and the mutation pointed at an expression that could not change its
		# outcome. Both defects were invisible because they cancelled out. Costs
		# one extra filtered bats run per row, which is what an anti-vacuity term
		# is worth.
		# `</dev/null` IS LOAD-BEARING, AND ITS ABSENCE MADE THIS TASK LIE. The row
		# loop is fed by `done <<<"$rows"`, so the rows are on this shell's stdin —
		# and `bats` reads stdin, so each invocation SWALLOWED the rows after the one
		# it was running. Measured 2026-08-23 on `claimed-keys`: three declared rows,
		# `declared` reached 2, and the third — `claimed-keys-adopts-speculated` —
		# was never applied, while the task reported "every one caught" and exited 0.
		#
		# That is this task's own defect reproduced inside its remedy: a report of
		# coverage over a set it never touched, which is exactly what CLOUD-418 was
		# filed about. It fails SILENTLY and in the passing direction, so nothing
		# turned red for as long as it has been there — and the tail of every
		# multi-row gate's declaration is what went unverified.
		clean_out="$(cd "$work" && "$bats_bin" --filter "$want" "$suite" 2>&1 </dev/null)"
		clean_rc=$?
		# "Named no case" is read BEFORE the status, because a filter matching
		# nothing is itself a non-zero exit on this runner — and reporting that as
		# "already red" would name the wrong defect to whoever has to fix it.
		if ! grep -qE '^(ok|not ok) ' <<<"$clean_out"; then
			echo "$gate/$slug names-no-case ($want)"
			failures=$((failures + 1))
			continue
		fi
		if [[ "$clean_rc" != 0 ]]; then
			echo "$gate/$slug case-already-red ($want)"
			failures=$((failures + 1))
			continue
		fi
		# THE FIFTH EVASION IS `names-no-case` FROM THE OTHER SIDE (CLOUD-480). A
		# filter matching NO case is refused above; a filter matching EVERY case was
		# not, and it is the same vacuity — the row stops naming a case, so redness
		# under mutation can come from anywhere in the suite and the declaration
		# reads as more than it proves. Measured on this task's own census sibling:
		# a row carrying a `|` inside its sed script was split into the wrong
		# fields, and the filter it ended up with had an EMPTY leading alternation
		# branch, which selects everything. All 14 cases ran; the row reported
		# caught; the case it names was never the reason.
		#
		# A comparison rather than a second bats run: the clean output already
		# carries one TAP line per selected case, and the suite's own total is a
		# `grep -c` over its case declarations.
		#
		# BOTH SPELLINGS, because a suite is not always observed in the form it was
		# written in: bats PREPROCESSES a file it runs, rewriting each `@test` line
		# into a `bats_test_function` call, and a suite can be read here after that
		# has happened. Counting only `@test` returned 0 over such a file, which
		# made `total` zero and switched this term off silently — the shape of
		# false green it exists to catch.
		selected=$(grep -cE '^(ok|not ok) ' <<<"$clean_out")
		total=$(grep -cE '^(@test |bats_test_function )' "$suite")
		if [[ "$selected" -ge "$total" ]] && [[ "$total" -gt 1 ]]; then
			echo "$gate/$slug filter-names-every-case ($want)"
			failures=$((failures + 1))
			continue
		fi

		# `-i.bak` and not the bare in-place flag (CLOUD-282): BSD sed reads the
		# next argument as the suffix, so the no-suffix spelling consumes the
		# script on a Mac. The backup is removed rather than kept — it exists
		# only to satisfy the one form both seds accept.
		if ! sed -i.bak "$script" "$work/$src"; then
			echo "$gate/$slug unappliable-mutation"
			failures=$((failures + 1))
			continue
		fi
		rm -f "$work/$src.bak"
		dirty="$src"
		# A mutation that changed nothing proves nothing, and would otherwise be
		# reported as caught or missed on the strength of an unrelated case.
		if cmp -s "$src" "$work/$src"; then
			echo "$gate/$slug inert-mutation"
			failures=$((failures + 1))
			continue
		fi
		# THE FOURTH EVASION, and it is the one the inertness term cannot see
		# (CLOUD-480). A row's pattern is a string that must also appear ON the
		# declaration line — so a pattern spelled literally matches its own row,
		# `cmp` reports a change, the gate's behaviour is untouched, and the
		# mutation SURVIVES every run while reading as enforced coverage. Measured:
		# `board-write-record`'s `overlap-frozen-at-write-time` had done exactly
		# that for its whole life. The remedy on the row is a character class
		# (`--n[a]med`), which matches the call and not the declaration; the
		# remedy here is refusing to accept a diff that touched declarations only.
		# `awk` rather than a `grep … | grep -q` pair: an early-exiting `grep` at the
		# end of a pipe under `pipefail` makes its producer's SIGPIPE the
		# pipeline's status, which is the hazard `pipefail-grep-check` gates.
		code_lines=$(diff -- "$src" "$work/$src" |
			awk '/^[<>] / && $0 !~ /^[<>] #MUTANT/ { n++ } END { print n + 0 }')
		if [[ "$code_lines" = 0 ]]; then
			echo "$gate/$slug self-mutating-row"
			failures=$((failures + 1))
			continue
		fi

		# Same reason as the clean run above: this must not eat the remaining rows.
		out="$(cd "$work" && "$bats_bin" --filter "$want" "$suite" 2>&1 </dev/null)"
		rc=$?
		# The named case must have RUN, and must have FAILED. A filter that matches
		# nothing exits 0 with no cases, which would read as "caught" — the
		# vacuous pass this whole task exists to refuse, one level up.
		if ! grep -qE '^(ok|not ok) ' <<<"$out"; then
			echo "$gate/$slug names-no-case ($want)"
			failures=$((failures + 1))
		elif [[ "$rc" = 0 ]]; then
			echo "$gate/$slug SURVIVED ($want)"
			failures=$((failures + 1))
		fi
	done <<<"$rows"
done

if [[ "$failures" != 0 ]]; then
	echo "::error:: mutant: $failures of $declared declared mutation(s) were not caught — a suite that passes on broken code is not coverage" >&2
	exit 1
fi
echo "mutant: $declared declared mutation(s) across ${gates//,/ }, every one caught"
