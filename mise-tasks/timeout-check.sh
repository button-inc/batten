#!/usr/bin/env bash
#MISE description="Gate: every workflow job's timeout-minutes carries a budget comment that justifies it — a pure function of the committed workflows, no network, no write"
#
# CLOUD-266. Every job in `.github/workflows/` already declares
# `timeout-minutes`, so the absence of a limit was never the problem. The problem
# is that the numbers are boilerplate: `15` for anything substantial, `5`/`10`
# for anything small, and no number derived from what its job costs. Measured
# over 25 `ci.yml` runs, the headroom over p95 was 3.4x for `ci`, 17.0x for
# `cross`, 10.3x for `darwin-link` and 75.0x for `final`.
#
# A cap at 17x or 75x of measured behaviour is not a limit. It cannot fail a job
# that is merely broken-slow, only one that is fully wedged, and it does so after
# burning the full fifteen minutes. More to the point it is inert as feedback:
# `ci` could double to eight minutes and every gate would stay green, so the
# number never tells anyone that CI got slower. A budget that only fires on
# catastrophe is a smoke alarm, not a thermostat.
#
# So this gate does not check the LIMIT. It checks that the limit is JUSTIFIED,
# and it makes the absence of a justification visible and unremovable:
#
#   no-timeout          a job declaring no `timeout-minutes` at all
#   no-budget           a `timeout-minutes` with no budget comment beside it
#   malformed-budget    a budget comment that does not parse
#   budget-arithmetic   a measured budget whose declared minutes disagree with
#                       its own stated p95 x multiplier
#
# THE BUDGET LIVES BESIDE THE VALUE IT BOUNDS, as a trailing comment on the same
# line, in one of exactly two forms:
#
#   timeout-minutes: 15 # budget: grandfathered measured=YYYY-MM-DD
#   timeout-minutes: 14 # budget: p95=267s x3 measured=YYYY-MM-DD
#
# A separate table would be a second file this gate has to hold in agreement with
# ten workflows, and a budget that can drift from the enforced value without
# failing is the second authority non-negotiable rule 6 warns about. Beside-the-
# value also handles the one structural oddity for free: `release-artifacts.yml`'s
# `dist` is a matrix job whose single `timeout-minutes` covers seven legs, and a
# table would have needed a key scheme to say so.
#
# `grandfathered` is not a synonym for exempt. It means "this value predates
# measurement and nobody has justified it yet" — honest, gateable, and visibly
# not a justification, so it reads as debt rather than as a decision. All
# fourteen jobs land grandfathered, which is why this gate is green on the tree
# it ships with: day one it changes no limit, it only makes the debt undeniable.
#
# ASCII `x` for the multiplier, not the multiplication sign the issue's prose
# used. The comparison is a byte match in awk, and a multibyte literal in a
# pattern is a portability hazard across locales for no gain. One spelling, so
# the grammar stays unambiguous.
#
# THE MULTIPLIER IS ONE REPO-WIDE CONSTANT, below, not a per-job field. A per-job
# multiplier is a per-job argument; the point of a single number is that
# loosening it anywhere is visible as loosening it everywhere.
#
# WHAT THIS DELIBERATELY DOES NOT DO: it never asks whether a budget still
# matches reality. That is a property of the world, not of the commit, and it
# belongs on a clock — `mise run timeout-drift`, on a schedule. The split is the
# `lock-complete` / `lock-currency` precedent `.claude/rules/toolchain.md` sets.
# `ci-wait` is untouched: a `timeout-minutes` breach is a terminal `failure`
# conclusion from GitHub, which `ci-wait` already reads correctly.
#
# SCOPE IS EVERY WORKFLOW, including the scheduled and release ones. That is the
# hole this fills. `ci-local-parity` covers only `pull_request`-triggered
# workflows on the stated ground that "a scheduled or release workflow is not on
# the landing path" — true for draft guards, false for spend, since
# `release-artifacts.yml`'s 30-minute matrix job is the most expensive thing here
# and nothing bounds it against measurement today.
#
# NOT A `batten.toml` RULE, asked and answered rather than skipped: the predicate
# is "this YAML key's value equals an arithmetic function of a number in an
# adjacent comment". `forbid` matches a literal substring and cannot compare
# integers; `command` is refused outright by `batten check`. The absent
# capability is a numeric comparison over a parsed structured field, and it is
# named here rather than quietly routed to bash. It is deliberately not filed as
# a capability gap: a rule kind that parsed GitHub Actions YAML would be
# consumer-specific by construction and would break non-negotiable rule 1 inside
# the crate hosting it.
#
# WHICH BYTES: the INDEX (`git show :<path>`), the `lock-complete` idiom — exactly
# the bytes a commit would carry, identical in CI and in a sandbox, immune to
# whatever an editor left in the tree. Explicit path arguments win, which is how
# the bats suite drives fixtures.
#
# Exit 0 pass, 1 violation, 2 could-not-look. `2` here is the `lock-complete`
# doctrine — "the gate could not read what it was asked to judge" — and NOT the
# `batten` binary's table, where 2 is the policy verdict. A gate reporting green
# over a file it failed to read is the failure that gets a gate switched off.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT budgetless-timeout-passes|s/^\texit 1$/\texit 0/|a job with no timeout-minutes is caught

set -euo pipefail

# The one repo-wide headroom multiplier a measured budget is derived with.
BUDGET_MULTIPLIER="${BATTEN_BUDGET_MULTIPLIER:-3}"

# Pointer-only per non-negotiable rule 4: the workflow, the line, the job, the
# declared value and the rule id — never the workflow body.
violations=0
report() {
	echo "$1" >&2
	violations=$((violations + 1))
}

# The files to judge. With arguments, those paths; without, every workflow in the
# index. Fixture mode is the argument form, so the suite never needs a git repo.
declare -a labels=()
declare -a sources=()
scratch=""
cleanup() { [[ -z "$scratch" ]] || rm -rf "$scratch"; }
trap cleanup EXIT

if [[ "$#" -gt 0 ]]; then
	for path in "$@"; do
		if [[ ! -f "$path" ]]; then
			echo "::error:: $path not found" >&2
			exit 2
		fi
		labels+=("$path")
		sources+=("$path")
	done
else
	scratch="$(mktemp -d)"
	# `git ls-files` names what is tracked; the blob comes from the index, so a
	# workflow edited but not staged is judged as the commit would carry it.
	tracked="$(git ls-files '.github/workflows/*.yml')"
	if [[ -z "$tracked" ]]; then
		echo "::error:: no tracked .github/workflows/*.yml — run from the repo, or pass paths" >&2
		exit 2
	fi
	while IFS= read -r path; do
		[[ -n "$path" ]] || continue
		blob="$scratch/$(basename "$path")"
		if ! git show ":$path" >"$blob" 2>/dev/null; then
			echo "::error:: $path is not in the index — stage it, or pass a path" >&2
			exit 2
		fi
		labels+=("$path")
		sources+=("$blob")
	done <<<"$tracked"
fi

# One pass per workflow, emitting a tab-separated record per job:
#
#   <job> <line-of-job-key> <line-of-timeout-or-0> <declared-or-empty> <budget>
#
# The job's own line is carried so `no-timeout` can point at the job rather than
# at the top of the file — there is no timeout line to name, and a pointer to
# line 1 is a pointer a reader cannot act on.
#
# The job walker is `ci-local-parity`'s, with its `guarded` test swapped for a
# `timeout-minutes` capture and `NR` kept for the pointer. `timeout-minutes` is
# anchored at exactly four spaces — job level. A step-level timeout sits deeper
# and is the step's business, not this gate's; matching it here would let a step
# satisfy a job's obligation.
jobs_of() {
	awk '
		function flush() {
			if (job != "") printf "%s\t%d\t%d\t%s\t%s\n", job, jobline, line, declared, budget
		}
		/^jobs:/ { injobs = 1; next }
		injobs && /^[a-z]/ { injobs = 0 }
		injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			flush()
			job = $1; sub(":", "", job); jobline = NR; line = 0; declared = ""; budget = ""
		}
		injobs && job != "" && /^    timeout-minutes:[[:space:]]*[0-9]+/ {
			line = NR
			value = $0
			sub(/^[[:space:]]*timeout-minutes:[[:space:]]*/, "", value)
			sub(/[^0-9].*$/, "", value)
			declared = value
			# The trailing comment, if any, from the first `#` onwards.
			budget = ""
			if (index($0, "#") > 0) budget = substr($0, index($0, "#"))
		}
		END { flush() }
	' "$1"
}

# `ceil(p95 * multiplier / 60)`, in integer arithmetic.
budget_minutes() {
	echo $(((($1 * $2) + 59) / 60))
}

checked=0
for index in "${!labels[@]}"; do
	label="${labels[$index]}"
	source="${sources[$index]}"

	# A workflow with no `jobs:` block is not a workflow this gate can judge, and
	# a silent pass over it is the failure mode `2` exists for.
	if ! grep -q '^jobs:' "$source"; then
		echo "::error:: $label declares no jobs: — unreadable as a workflow" >&2
		exit 2
	fi

	records="$(jobs_of "$source")"
	if [[ -z "$records" ]]; then
		echo "::error:: $label has a jobs: block but no job keys under it — unparseable" >&2
		exit 2
	fi

	while IFS=$'\t' read -r job jobline line declared budget; do
		[[ -n "$job" ]] || continue
		checked=$((checked + 1))

		if [[ "$line" = "0" ]]; then
			report "$label:$jobline $job - no-timeout"
			continue
		fi

		if [[ -z "$budget" ]]; then
			report "$label:$line $job $declared no-budget"
			continue
		fi

		# Two accepted forms, matched whole so a comment that merely mentions the
		# word cannot pass. `=~` on a here-string keeps `pipefail-grep-check` happy.
		measured='^#[[:space:]]*budget:[[:space:]]*p95=([0-9]+)s[[:space:]]+x([0-9]+)[[:space:]]+measured=([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]*$'
		grandfathered='^#[[:space:]]*budget:[[:space:]]*grandfathered[[:space:]]+measured=([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]*$'

		if [[ $budget =~ $grandfathered ]]; then
			continue
		fi

		if [[ $budget =~ $measured ]]; then
			p95="${BASH_REMATCH[1]}"
			multiplier="${BASH_REMATCH[2]}"
			if [[ "$multiplier" != "$BUDGET_MULTIPLIER" ]]; then
				report "$label:$line $job $declared budget-multiplier (x$multiplier, repo constant is x$BUDGET_MULTIPLIER)"
				continue
			fi
			expected="$(budget_minutes "$p95" "$multiplier")"
			if [[ "$declared" != "$expected" ]]; then
				report "$label:$line $job $declared budget-arithmetic (p95=${p95}s x$multiplier is ${expected}m)"
			fi
			continue
		fi

		report "$label:$line $job $declared malformed-budget"
	done <<<"$records"
done

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: timeout-check: $violations job(s) without a justified budget. Every job needs a trailing comment beside its timeout-minutes: either \`# budget: grandfathered measured=YYYY-MM-DD\` (the value predates measurement) or \`# budget: p95=<n>s x$BUDGET_MULTIPLIER measured=YYYY-MM-DD\`, where the declared minutes equal ceil(p95 x $BUDGET_MULTIPLIER / 60)." >&2
	exit 1
fi

echo "timeout-check: $checked job(s) across ${#labels[@]} workflow(s), every timeout justified"
