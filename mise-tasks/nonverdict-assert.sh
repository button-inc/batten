#!/usr/bin/env bash
#MISE description="Gate: how many recent CI jobs failed WITHOUT reaching a verdict is under budget (reads `nonverdict-scan` records on stdin)"
#
# CLOUD-484. A job that dies in provisioning — checkout, the toolchain install, a
# cache restore — spends its runner minutes, reds the branch,
# and answers nothing. Every occurrence then costs a human or an agent the time to
# discover it was never a verdict at all: CLOUD-404 has three, and the one on #376
# sent an agent to reproduce a `commit-lint` failure that passes locally because
# `commit-lint` never linted anything.
#
# CLOUD-483 stops `land` MISREADING one in the moment. This answers the question
# neither of those does: **how often**. Without it the escalation trigger is
# "whoever gets bitten next", so a step change — a runner-image regression, an
# upstream action shipping a bad release, a cache-key change that cold-starts every
# job — is invisible until it has been paid for repeatedly.
#
# THIS DECIDES; IT DOES NOT MEASURE. `mise run nonverdict-scan` reads the API and
# emits records; this is a pure function of those records, the same split
# `bench`/`bench-assert` uses and for the same reason: a measurement needs the
# network and a token, a decision needs neither, so keeping them apart is what lets
# `tests/nonverdict-assert.bats` run in the hk gate on every commit while the
# measurement runs on a clock.
#
# WHY A GATE AND NOT A REPORT. Non-negotiable rule 2: a log without a gate is
# sensor only. A rate that rises has to fail something, or it becomes another
# artifact nobody opens — which is the failure mode this issue was filed against
# twice, both times by someone deciding the number was not worth collecting.
#
# Exit 0 under budget / 1 over / 2 could not look. `2` is the `lock-complete`,
# `timeout-check` and `bench-assert` doctrine — "the gate could not read what it
# was asked to judge" — and it is deliberately distinct from a violation, because a
# gate that reports green over input it failed to parse is the failure that gets a
# gate switched off.
set -euo pipefail

# The budget: how many non-verdict job failures the window may carry before this
# fails. Written here as data, with a raise-only env override — the placement
# `bench-assert`'s BUDGETS, `branch-age-check`'s BRANCH_MAX_AGE_DAYS and
# `timeout-drift`'s multipliers all use.
#
# NOT in `batten.toml [ci]`: that table is a projection of what the GitHub HOST
# enforces and `ci-drift` polices it against the live ruleset, so a key with no
# host counterpart would make that gate judge something nothing declares. NOT in
# `mise.toml [env]` either: that is for values two or more programs share, and this
# one has a single reader.
#
# Two, not zero. One provisioning failure in a window is the platform having a bad
# afternoon and is not actionable; a third in the same window is a pattern, and the
# whole point is to hear about the pattern before the minutes are spent. The
# override is what lets the suite point the budget at a fixture.
MAX_NONVERDICT="${BATTEN_NONVERDICT_MAX:-2}"

# Pointer-only per non-negotiable rule 4: run ids, job names, step names and
# counts. `nonverdict-scan` never emits a log body, so there is none to leak here.
report() {
	echo "  $1" >&2
}

records=$(cat)
if [[ -z "${records//[[:space:]]/}" ]]; then
	echo "::error:: nonverdict-assert: stdin is empty — pipe \`mise run nonverdict-scan\` records in (redirect to a file, then read it back; a pipeline would hand this gate's exit status to its last stage)." >&2
	exit 2
fi

# Records are TAB-separated, because job and step names carry spaces
# ("Run mise run commit-lint", "darwin-link (aarch64-apple-darwin)") and a
# space-separated key=value stream cannot represent them. One kind per line:
#
#   nonverdict\trun=<id>\tjob=<name>\tstep=<name>
#   verdict\trun=<id>\tjob=<name>\tstep=<name>
#   window\truns=<n>\tfailed_jobs=<k>\tnonverdict=<m>\tverdict=<v>\tunreadable=<u>
#
# `verdict` lines are carried so the ratio is derivable and so a window that found
# only verdicts is distinguishable from one that found nothing — the same reason
# `capture` stores a zero-byte stream rather than skipping it.
#
# Literal-pattern awk, never a `-v` regex: a pattern reaching awk through `-v` goes
# through assignment escape processing first, which `mise run awk-regex-check`
# refuses for being implementation-defined.
summary=$(awk -F'\t' '$1 == "window" { print; found = 1 } END { exit !found }' <<<"$records") || summary=""
if [[ -z "$summary" ]]; then
	echo "::error:: nonverdict-assert: the records carry no \`window\` summary line, so there is no window to judge — did \`nonverdict-scan\` complete?" >&2
	exit 2
fi

# More than one summary means two scans were concatenated, and the counts below
# would silently describe neither window.
if [[ "$(awk -F'\t' '$1 == "window"' <<<"$records" | grep -c .)" != "1" ]]; then
	echo "::error:: nonverdict-assert: stdin carries more than one \`window\` summary — two scans were concatenated, and a count over both describes neither." >&2
	exit 2
fi

field() {
	awk -F'\t' -v key="$1" '
		$1 == "window" {
			for (i = 2; i <= NF; i++) {
				n = index($i, "=")
				if (n > 0 && substr($i, 1, n - 1) == key) { print substr($i, n + 1); exit }
			}
		}
	' <<<"$records"
}

runs=$(field runs)
nonverdict=$(field nonverdict)
unreadable=$(field unreadable)

for pair in "runs:$runs" "nonverdict:$nonverdict" "unreadable:$unreadable"; do
	name="${pair%%:*}"
	value="${pair#*:}"
	if [[ -z "$value" ]] || [[ "$value" != "${value#*[^0-9]}" ]]; then
		echo "::error:: nonverdict-assert: the \`window\` summary carries no readable \`$name\` count, so the window cannot be judged." >&2
		exit 2
	fi
done

# A scan that could not read part of its window judged less than it claims. This is
# `bench-assert`'s partial-coverage rule: "a run that measured two of three paths
# and reported green over the two is exactly the partial-coverage false green".
if [[ "$unreadable" != "0" ]]; then
	echo "::error:: nonverdict-assert: the scan could not read $unreadable run(s) in its window, so a green verdict here would cover less than it claims." >&2
	report "re-run \`mise run nonverdict-scan\`; a persistent read failure is a token or rate-limit problem, not a clean window"
	exit 2
fi

# ANTI-VACUITY. A window with no runs in it cannot fire, and a gate that cannot
# fire must not be indistinguishable from one that found nothing — this repo has
# been bitten by that twice (`finding-sink-check`, `bench-assert`).
if [[ "$runs" = "0" ]]; then
	echo "nonverdict-assert: no runs in the window — nothing to judge" >&2
	exit 0
fi

if [[ "$nonverdict" -le "$MAX_NONVERDICT" ]]; then
	echo "nonverdict-assert: $nonverdict of $runs run(s) failed without reaching a verdict (budget $MAX_NONVERDICT)"
	exit 0
fi

echo "::error:: nonverdict-assert: $nonverdict job(s) in the last $runs run(s) failed WITHOUT reaching a verdict, over the budget of $MAX_NONVERDICT. Those runs spent minutes and answered nothing." >&2
while IFS= read -r line; do
	[[ -n "$line" ]] || continue
	report "$(awk -F'\t' '{ sub(/^nonverdict\t/, ""); print }' <<<"$line")"
done <<<"$(awk -F'\t' '$1 == "nonverdict"' <<<"$records")"
report "each is a job that died before any \`mise run\` step; see CLOUD-404 for the recurring upstream cause and CLOUD-483 for the in-loop remedy"
exit 1
