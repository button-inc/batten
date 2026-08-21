#!/usr/bin/env bash
#MISE description="Report (never gate) whether each job's committed timeout budget still matches measured reality — a question about the world, so it runs on a clock"
#
# CLOUD-266, the other half. `timeout-check` asks a question about the commit:
# is every timeout justified? This asks a question about the world: is the
# justification still TRUE? A property of the commit belongs in the gate, a
# property of the world belongs on a clock — the `lock-complete` /
# `lock-currency` split `.claude/rules/toolchain.md` sets.
#
# It reports and never blocks the landing path. On drift it fails its own
# scheduled workflow run and does nothing else: no issue filed, no comment
# posted, exactly the posture `lock-currency.yml` states in its header. Here a
# failure means a budget no longer matches reality, not that anything is broken.
#
# DRIFT IS REPORTED IN BOTH DIRECTIONS, and the loose direction is the point. A
# budget that has gone slack because the job got faster is the ratchet this issue
# exists for; a report that only complained about tightness would let every
# number rot upward forever. So:
#
#   drift-loose   the declared minutes are well above what the measurement now
#                 justifies — the number to tighten
#   drift-tight   the measurement has outgrown the declared minutes — the number
#                 to raise, before it starts failing healthy runs
#   grandfathered a dated debt entry that now HAS a usable sample, so it can be
#                 converted to a measured budget. This is the prompt; converting
#                 it is a deliberate commit, never a bot re-baselining the number
#                 it is supposed to defend (§4: nothing derived).
#   unmeasurable  fewer than MIN_SAMPLES successful runs in the window
#
# A SMALL SAMPLE MUST REPORT `unmeasurable`, NEVER A NUMBER. Ten of the fourteen
# jobs run weekly or on release, so a naive p95 over a two-week window would
# compute a confident value from two samples and propose tightening a release job
# on it. Below the stated minimum the job is reported as unmeasurable, which is
# itself the useful signal about a job nobody can characterise.
#
# Matrix legs pool. `release-artifacts.yml`'s `dist` declares one
# `timeout-minutes` covering seven targets, and the API reports each leg under
# `dist (<target>)`. One budget bounds them all, so every leg's duration feeds one
# distribution — matched on the job key, or the key followed by ` (`.
#
# Exit 0 clean, 1 drift, 2 could-not-look. `2` for an absent `gh`, a failed query
# or an unreadable workflow: reporting a healthy budget as drifted on a network
# blip is the failure mode that gets a scheduled gate switched off.
set -euo pipefail

# The one repo-wide headroom multiplier, the same constant `timeout-check` gates.
BUDGET_MULTIPLIER="${BATTEN_BUDGET_MULTIPLIER:-3}"
# Below this many successful runs a job is unmeasurable, not fast.
MIN_SAMPLES="${BATTEN_BUDGET_MIN_SAMPLES:-5}"
# How many recent successful runs per workflow to read.
WINDOW="${BATTEN_BUDGET_WINDOW:-25}"
# How far a declared value may sit from what the measurement justifies before it
# is called loose. A budget is a ceiling, not a target, so some slack is correct.
SLACK_MINUTES="${BATTEN_BUDGET_SLACK:-5}"

if ! command -v gh >/dev/null 2>&1; then
	echo "::error:: gh is not on PATH — cannot read the Actions API" >&2
	exit 2
fi

workflows=".github/workflows"
[ "$#" -eq 0 ] || workflows="$1"
if [ ! -d "$workflows" ]; then
	echo "::error:: $workflows is not a directory" >&2
	exit 2
fi

drift=0
report() {
	echo "$1" >&2
	drift=$((drift + 1))
}

# Seconds between two RFC 3339 instants. GNU `date` on the runner; the bats suite
# drives the same path through its stub.
seconds_between() {
	local from to
	from=$(date -d "$1" +%s 2>/dev/null) || return 1
	to=$(date -d "$2" +%s 2>/dev/null) || return 1
	echo $((to - from))
}

# The p95 of a newline-separated list of integers: the ceil(0.95 * n)-th smallest.
p95_of() {
	local sorted count index
	sorted=$(sort -n <<<"$1")
	count=$(grep -c . <<<"$sorted")
	index=$((((95 * count) + 99) / 100))
	[ "$index" -ge 1 ] || index=1
	sed -n "${index}p" <<<"$sorted"
}

# `ceil(p95 * multiplier / 60)`, the same arithmetic `timeout-check` gates.
budget_minutes() {
	echo $(((($1 * $2) + 59) / 60))
}

# The declared budget per job, read from the workflow itself so this task and the
# gate can never disagree about what is committed.
jobs_of() {
	awk '
		function flush() {
			if (job != "") printf "%s\t%s\t%s\n", job, declared, budget
		}
		/^jobs:/ { injobs = 1; next }
		injobs && /^[a-z]/ { injobs = 0 }
		injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			flush()
			job = $1; sub(":", "", job); declared = ""; budget = ""
		}
		injobs && job != "" && /^    timeout-minutes:[[:space:]]*[0-9]+/ {
			value = $0
			sub(/^[[:space:]]*timeout-minutes:[[:space:]]*/, "", value)
			sub(/[^0-9].*$/, "", value)
			declared = value
			budget = ""
			if (index($0, "#") > 0) budget = substr($0, index($0, "#"))
		}
		END { flush() }
	' "$1"
}

checked=0
for wf in "$workflows"/*.yml; do
	[ -e "$wf" ] || continue
	file="$(basename "$wf")"

	# Successful runs only: a cancelled or failed run's duration says nothing
	# about what the job costs when it works.
	if ! runs=$(gh api "repos/{owner}/{repo}/actions/workflows/$file/runs?status=success&per_page=$WINDOW" \
		--jq '.workflow_runs[].id' 2>/dev/null); then
		echo "::error:: cannot read runs for $file" >&2
		exit 2
	fi

	# One duration per successful job, keyed by the API's job name.
	durations=""
	while IFS= read -r run; do
		[ -n "$run" ] || continue
		if ! legs=$(gh api "repos/{owner}/{repo}/actions/runs/$run/jobs" \
			--jq '.jobs[] | select(.conclusion == "success") | [.name, .started_at, .completed_at] | @tsv' 2>/dev/null); then
			echo "::error:: cannot read jobs for run $run" >&2
			exit 2
		fi
		while IFS=$'\t' read -r name started completed; do
			[ -n "$name" ] || continue
			elapsed=$(seconds_between "$started" "$completed") || continue
			[ "$elapsed" -ge 0 ] || continue
			durations+="$name	$elapsed"$'\n'
		done <<<"$legs"
	done <<<"$runs"

	while IFS=$'\t' read -r job declared budget; do
		[ -n "$job" ] || continue
		[ -n "$declared" ] || continue
		checked=$((checked + 1))

		# The job key, or the key followed by " (" — which is how a matrix leg
		# reports. Every leg feeds one distribution, because one timeout bounds
		# them all.
		samples=$(awk -F'\t' -v job="$job" \
			'$1 == job || index($1, job " (") == 1 { print $2 }' <<<"$durations")
		count=$(grep -c . <<<"$samples" || true)

		if [ "$count" -lt "$MIN_SAMPLES" ]; then
			report "$file $job $declared unmeasurable ($count/$MIN_SAMPLES samples)"
			continue
		fi

		p95=$(p95_of "$samples")
		justified=$(budget_minutes "$p95" "$BUDGET_MULTIPLIER")

		if [[ $budget =~ grandfathered ]]; then
			report "$file $job $declared grandfathered (p95=${p95}s x$BUDGET_MULTIPLIER is ${justified}m — convert it)"
			continue
		fi

		if [ "$declared" -lt "$justified" ]; then
			report "$file $job $declared drift-tight (p95=${p95}s x$BUDGET_MULTIPLIER needs ${justified}m)"
		elif [ "$declared" -gt $((justified + SLACK_MINUTES)) ]; then
			report "$file $job $declared drift-loose (p95=${p95}s x$BUDGET_MULTIPLIER justifies ${justified}m)"
		fi
	done <<<"$(jobs_of "$wf")"
done

if [ "$drift" -ne 0 ]; then
	echo "::error:: timeout-drift: $drift budget(s) no longer match reality. This is a report, not a gate — nothing is broken and no branch is at fault. Re-derive the ones named above and commit the new comment; a bot must not re-baseline the number it is supposed to defend." >&2
	exit 1
fi

echo "timeout-drift: $checked job(s), every budget still matches its measurement"
