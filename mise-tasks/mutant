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
# enforced; a gate IN it with no declaration FAILS here, and a gate not in it is a
# filed row rather than a silent exemption. Declaring all forty-odd gates at once
# would put branch age — the thing that multiplies laps and CI runs — on the
# critical path of the change that reduces them.
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
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

fail_input() {
	echo "::error:: mutant: $*" >&2
	exit 2
}

gates="${MUTANT_GATES:-}"
[ -n "$gates" ] ||
	fail_input "MUTANT_GATES is unset — run this through \`mise run mutant\`, which is where the enforced set is declared. An empty set makes this a task that silently covers nothing, which is the defect it exists to refuse."

bats_bin="tests/bats/bin/bats"
[ -x "$bats_bin" ] ||
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

failures=0
declared=0

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
	src="mise-tasks/$gate"
	[ -f "$src" ] || src="policy/$gate.rego"
	suite="tests/$gate.bats"
	[ -f "$src" ] || {
		echo "$gate no-such-gate"
		failures=$((failures + 1))
		continue
	}
	[ -f "$suite" ] || {
		echo "$gate no-suite ($suite)"
		failures=$((failures + 1))
		continue
	}

	rows="$(sed -n 's/^#MUTANT //p' "$src")"
	# THE ANTI-VACUITY TERM, AND IT IS THE WHOLE DESIGN. A listed gate with no
	# declaration is a failure, not a skip. Without this the task reports success
	# over a set it never touched — which is exactly the "reads as coverage"
	# defect CLOUD-418 was filed about, reproduced by its own remedy.
	[ -n "$rows" ] || {
		echo "$gate no-mutant-declared"
		failures=$((failures + 1))
		continue
	}

	while IFS='|' read -r slug script want; do
		[ -n "${slug:-}" ] || continue
		declared=$((declared + 1))
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
		clean_out="$(cd "$work" && "$bats_bin" --filter "$want" "$suite" 2>&1)"
		clean_rc=$?
		# "Named no case" is read BEFORE the status, because a filter matching
		# nothing is itself a non-zero exit on this runner — and reporting that as
		# "already red" would name the wrong defect to whoever has to fix it.
		if ! grep -qE '^(ok|not ok) ' <<<"$clean_out"; then
			echo "$gate/$slug names-no-case ($want)"
			failures=$((failures + 1))
			continue
		fi
		if [ "$clean_rc" != 0 ]; then
			echo "$gate/$slug case-already-red ($want)"
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
		# A mutation that changed nothing proves nothing, and would otherwise be
		# reported as caught or missed on the strength of an unrelated case.
		if cmp -s "$src" "$work/$src"; then
			echo "$gate/$slug inert-mutation"
			failures=$((failures + 1))
			continue
		fi

		out="$(cd "$work" && "$bats_bin" --filter "$want" "$suite" 2>&1)"
		rc=$?
		# The named case must have RUN, and must have FAILED. A filter that matches
		# nothing exits 0 with no cases, which would read as "caught" — the
		# vacuous pass this whole task exists to refuse, one level up.
		if ! grep -qE '^(ok|not ok) ' <<<"$out"; then
			echo "$gate/$slug names-no-case ($want)"
			failures=$((failures + 1))
		elif [ "$rc" = 0 ]; then
			echo "$gate/$slug SURVIVED ($want)"
			failures=$((failures + 1))
		fi
	done <<<"$rows"
done

if [ "$failures" != 0 ]; then
	echo "::error:: mutant: $failures of $declared declared mutation(s) were not caught — a suite that passes on broken code is not coverage" >&2
	exit 1
fi
echo "mutant: $declared declared mutation(s) across ${gates//,/ }, every one caught"
