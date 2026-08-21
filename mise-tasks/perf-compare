#!/usr/bin/env bash
#MISE description="Gate: this branch has not made an invocation path measurably slower than its merge base (reads a paired measurement on stdin)"
#
# CLOUD-172, and the half that reaches someone who can still act. A recorded
# series nobody opens changes no behaviour; a failing check on the pull request
# that caused the regression arrives while the author still has the context to
# fix it.
#
# A PURE FUNCTION OF STDIN, like `perf-assert`, `graph-check` and `claim-check`
# before it: agents fetch, gates decide. `mise run perf-pair` is the driver that
# produces the paired measurement; this decides over it. That split is what lets
# `tests/perf-compare.bats` exercise every verdict on every commit in
# milliseconds, with no build, no hyperfine and no worktree.
#
# THE VERDICT IS A RATIO, NEVER AN ABSOLUTE. This is the whole design, and it is
# what replaces the instruction counts CLOUD-172 asked for. `mise registry
# valgrind` reports "tool not found in registry", so callgrind cannot be pinned
# and `batten.toml`'s `no-source-built-tool` rule forbids compiling it — wall
# clock is the only metric available. Wall clock on a shared runner is exactly
# the metric the issue warns "both hides real regressions and invents fake
# ones", and it is right about the ABSOLUTE number: a runner contending with
# other tenants can double a 3ms measurement for reasons no commit caused.
#
# What it cannot do is double ONE ARM of a pair measured back to back on that
# same runner in that same second. Machine-level variance is common-mode across
# the pair and divides out. So the driver builds both binaries and hands this
# gate two measurements taken together, and the question asked here is "did HEAD
# get slower THAN ITS OWN BASE, on one machine, at one moment" — which is a
# property of the change, and the only latency question a shared runner can
# answer honestly.
#
# THE THRESHOLD IS MEASURED, NOT ASSERTED — CLOUD-74's move, applied to this
# gate's own constant. The number below is not a guess about what feels
# reasonable; it is derived from the noise floor of a null comparison, the same
# binary measured as both arms. See NOISE_FLOOR beside it.
#
# Exit 0 within threshold / 1 a path regressed past it / 2 could not look.
set -euo pipefail

# THE THRESHOLD, and the measurement it comes from.
#
# NULL COMPARISON, measured 2026-08-11 on a 4-core x86_64 container: the
# identical binary as both arms, 100 runs each after 10 warmups, ten repeats
# across the three paths — 30 ratios of a comparison that by construction
# measures nothing. They spread **0.966 to 1.102**. So a 10% swing is what this
# experiment produces on a quiet machine when NOTHING changed, and a threshold
# anywhere near 1.10 would be a coin flip rather than a gate.
#
# 1.30 sits clear of that measured maximum with room for a busier runner. The
# asymmetry is deliberate: a false failure costs a confused author and, repeated,
# gets the gate switched off, while a regression small enough to slip under 1.30
# is caught by the trunk series instead. A gate people trust that fires late
# beats a gate that fires early and gets deleted.
#
# It is also the right ORDER of sensitivity for what this gate is actually for.
# The regressions worth blocking are not drift — they are a commit that made the
# hook path do real work: a config read, a git invocation, a filesystem walk.
# Against a 2.6ms base those are multiples, not percentages.
#
# Re-measure with `mise run perf-pair --null`; that flag exists so the floor
# stays checkable rather than historical.
REGRESSION_RATIO="${BENCH_REGRESSION_RATIO:-1.30}"
NOISE_FLOOR="1.102" # measured null maximum, n=30; reported, never compared against

# ACCEPTED REGRESSIONS, and why this is a table rather than a bigger threshold.
#
# A raised `REGRESSION_RATIO` is a repo-wide answer to a one-branch question: it
# stops the gate asking about every path on every future PR, and nothing records
# what it was raised for. Each row here accepts ONE path at ONE ratio until ONE
# date, with the reason attached, so the gate keeps asking everything else at
# 1.30 and this decision expires by itself.
#
# `path|ratio|expires|reason`. A row that lapses stops exempting rather than
# quietly continuing (`prebuilt-lint`'s own waiver semantics, CLOUD-92); a row
# with no reason is bad input and refuses, because an exemption nobody explained
# is indistinguishable from a threshold nobody defends.
#
# EXEMPT ROWS ARE REPORTED ON EVERY RUN, never silent. An accepted regression
# that stops being visible is a raised threshold with extra steps.
EXEMPT="wired|1.60|2026-11-30|CLOUD-843: a migrated gate compiles per mediated call. Measured: the same predicate against CLOUD-857's projected input.call.segments is 1.17x, so this expires with that row rather than standing on its own"

# Injectable so the lapse case is testable without waiting for a date to pass —
# the shape `in-progress-drain` uses for `WIP_DRAIN_TODAY`.
TODAY="${PERF_EXEMPT_TODAY:-$(date -u +%F)}"

# The ratio this path is allowed to reach, and the reason, or empty for neither.
exemption_for() { # exemption_for <path>
	local path ratio expires reason
	while IFS='|' read -r path ratio expires reason; do
		[ -n "${path:-}" ] || continue
		[ "$path" = "$1" ] || continue
		if [ -z "${reason:-}" ] || [ -z "${expires:-}" ] || [ -z "${ratio:-}" ]; then
			echo "::error:: perf-compare: the exemption for '$path' is missing a ratio, an expiry or a reason. An exemption nobody explained is a threshold nobody defends." >&2
			exit 2
		fi
		if [[ "$expires" < "$TODAY" ]]; then
			echo "::error:: perf-compare: the exemption for '$path' lapsed on $expires and no longer applies. Fix the regression or take the decision again with a new date." >&2
			return 1
		fi
		printf '%s\t%s\t%s' "$ratio" "$expires" "$reason"
		return 0
	done <<<"$EXEMPT"
	return 1
}

fail=0
reported=0
accepted_count=0
report() {
	if [ "$reported" = 0 ]; then
		echo "::error:: perf-compare: an invocation path is measurably slower than the merge base (threshold ${REGRESSION_RATIO}x, measured noise floor ${NOISE_FLOOR}x):" >&2
		reported=1
	fi
	echo "  $1" >&2
	fail=1
}

# The paired records. Two blocks, distinguished by an `arm=` field: `base` for
# the merge-base binary, `head` for this branch's. Anything else is unreadable.
pairs="$(cat)"
if [ -z "${pairs//[[:space:]]/}" ]; then
	echo "::error:: perf-compare: stdin is empty — redirect \`mise run perf-pair\` to a file and read it back. No verdict." >&2
	exit 2
fi

# Literal awk patterns rather than a `-v` regex (`mise run awk-regex-check`).
# A line that is neither a paired record nor blank is noise in a stream that
# carries verdict input, and noise is "could not look", never a pass.
parsed="$(awk '
	/^arm=/ {
		arm = ""; id = ""; p50 = ""
		for (i = 1; i <= NF; i++) {
			split($i, kv, "=")
			if (kv[1] == "arm")  arm = kv[2]
			if (kv[1] == "path") id  = kv[2]
			if (kv[1] == "p50")  p50 = kv[2]
		}
		if ((arm != "base" && arm != "head") || id == "" || p50 == "" || p50 + 0 != p50 || p50 == "0") {
			print "MALFORMED\t" NR
			next
		}
		print "OK\t" arm "\t" id "\t" p50
		next
	}
	/[^[:space:]]/ { print "MALFORMED\t" NR }
' <<<"$pairs")"

malformed="$(awk -F'\t' '$1=="MALFORMED"{print $2}' <<<"$parsed")"
if [ -n "$malformed" ]; then
	echo "::error:: perf-compare: stdin carries lines that are not paired records, so no comparison is possible:" >&2
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		echo "  stdin:$line: not an \`arm=<base|head> path=<id> p50=… p95=… mean=… runs=…\` record" >&2
	done <<<"$malformed"
	exit 2
fi

# p50, not p95, and the reason is the pairing. p95 is the right statistic for an
# absolute budget (`perf-assert`), because a hook's worst case is what an agent
# feels. It is the wrong one for a ratio: the tail is where a runner's
# contention lands, so a p95 ratio is the noisiest number available, while p50
# is the most stable estimate of what the binary itself costs. The budget gate
# still holds the tail; this one holds the shape.
heads="$(awk -F'\t' '$1=="OK" && $2=="head" {print $3"\t"$4}' <<<"$parsed")"
if [ -z "$heads" ]; then
	echo "::error:: perf-compare: no \`head\` measurements on stdin — the driver produced no arm to judge. No verdict." >&2
	exit 2
fi

while IFS=$'\t' read -r id head_p50; do
	[ -n "$id" ] || continue
	base_p50="$(awk -F'\t' -v want="$id" '$1=="OK" && $2=="base" && $3==want {print $4; exit}' <<<"$parsed")"
	# An unpaired path is could-not-look, never a pass: it means the base build
	# failed to measure that path, and reporting green over a comparison that did
	# not happen is the partial-coverage false green this repo keeps re-meeting.
	if [ -z "$base_p50" ]; then
		echo "::error:: perf-compare: path '$id' was measured on head but not on base, so it was never compared. No verdict." >&2
		exit 2
	fi
	# awk for the arithmetic: the values are fractional milliseconds and `[ ]`
	# compares integers only.
	ratio="$(awk -v h="$head_p50" -v b="$base_p50" 'BEGIN { printf "%.3f", h / b }')"
	limit="$REGRESSION_RATIO"
	accepted=""
	if allowed="$(exemption_for "$id")"; then
		IFS=$'\t' read -r exempt_ratio exempt_until exempt_why <<<"$allowed"
		# The exemption RAISES this path's bar and never lowers it: a branch that
		# is already inside the ordinary threshold is judged by the ordinary
		# threshold, so an accepted regression cannot become a licence to drift
		# up to it.
		if awk -v e="$exempt_ratio" -v l="$limit" 'BEGIN { exit !(e > l) }'; then
			limit="$exempt_ratio"
			accepted="$exempt_until|$exempt_why"
		fi
	fi
	if awk -v r="$ratio" -v limit="$limit" 'BEGIN { exit !(r > limit) }'; then
		report "$id: base p50=${base_p50}ms -> head p50=${head_p50}ms (${ratio}x)"
	elif [ -n "$accepted" ] && awk -v r="$ratio" -v l="$REGRESSION_RATIO" 'BEGIN { exit !(r > l) }'; then
		# Loud on every run, on stderr beside the refusals, because this is the
		# line that stops an accepted regression from becoming invisible.
		echo "::warning:: perf-compare: $id is ${ratio}x, past the ${REGRESSION_RATIO}x threshold, accepted until ${accepted%%|*} — ${accepted#*|}" >&2
		accepted_count=$((accepted_count + 1))
	fi
done <<<"$heads"

[ "$fail" = 0 ] || exit 1
# The summary must not claim more than the run established. Saying "every path is
# within 1.30x" over a run that accepted one past it is the same false green this
# gate exists to refuse, one layer up in its own output.
if [ "$accepted_count" != 0 ]; then
	echo "perf-compare: every measured path is within ${REGRESSION_RATIO}x of the merge base, except $accepted_count accepted above"
else
	echo "perf-compare: every measured path is within ${REGRESSION_RATIO}x of the merge base"
fi
