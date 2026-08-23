#!/usr/bin/env bash
#MISE description="Gate: the external analyzer's verdict on this SHA (0 pass / 1 red / 2 could not look / 3 no answer yet)"
#
# WHY THIS IS NOT A `needs:` ENTRY. `ci.yml`'s `final` is the single fan-in every
# other leg reports through, and branch protection points at it so that adding a
# job never needs a ruleset change. That aggregation works by `needs:`, and
# `needs:` resolves only to jobs in the SAME WORKFLOW FILE. `SonarCloud Code
# Analysis` is a check-run posted on the commit by a GitHub App, so there is no
# job for `final` to name — the fan-in cannot reach it at any amount of workflow
# editing. Measured on #348: the check-run is there, `success`, completed 12s
# after the push, beside the six Actions jobs, and binding nothing.
#
# So `final` reads it by NAME instead, through this gate, and stays the one
# thing branch protection requires. That is the whole reason this is a gate in
# the tree rather than an edit to the host ruleset: the merge contract does not
# move, and the new verdict rides in on the check that already carries every
# other one.
#
# WHY NOT `CI_REQUIRED_CHECKS`. That roster names the checks THIS REPOSITORY
# produces, and `ci-local-parity` holds it to the `pull_request` jobs in both
# directions — a name matching no job fails the gate, which is what keeps it
# from rotting. An external analyzer is by definition no job of ours, so putting
# it there would mean loosening the sensor that makes the roster trustworthy.
# `land`'s `graded_runs` reads the same roster and must not see this name for a
# second reason (CLOUD-327): Sonar is not draft-gated, so it grades on the draft
# push, and counting it would read a head as "answered" while every check of
# ours is still a draft-era skip.
#
# THE READING, and why `absent` is a pass. Same shape and same rules as
# `checks-green`, deliberately — one name is judged by its LATEST run
# (CLOUD-436), because a SHA accumulates a check-run per event and a superseded
# one must not speak. Absent is not skipped: an analyzer that declines to grade
# a PR produces no run at all, and failing on that would wedge every PR it has
# no opinion about. Pending is not a pass either — it is exit 3, and the caller
# decides whether to poll again or call it.
#
# Injectable through $SONAR_GATE_RUNS as TSV lines
# `status<TAB>conclusion<TAB>name<TAB>started_at<TAB>id`, which is how the suite
# runs with no network and how a caller that already fetched hands the body over
# rather than paying for it twice.
#
# Output is pointer-only per non-negotiable rule 4: a `<conclusion> <check>`
# coordinate and nothing from the analysis itself — no issue text, no file, no
# rule name. The details_url on the check-run is where a human reads that.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT red-analysis-passes|s/^\texit 1$/\texit 0/|a failed analysis is red, and named

set -uo pipefail

fail_input() {
	echo "::error:: sonar-gate: $*" >&2
	exit 2
}

# The one place the analyzer's check-run name is written. Overridable so the
# suite can exercise the reader without pinning a vendor string into every case.
check="${SONAR_CHECK_NAME:-SonarCloud Code Analysis}"

sha="${SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"

# `${VAR+set}` rather than emptiness: an explicitly empty reading is a real state
# — a SHA carrying no check-run yet — and must answer from that rather than fall
# through to the network.
if [[ -n "${SONAR_GATE_RUNS+set}" ]]; then
	runs="$SONAR_GATE_RUNS"
else
	[[ -n "$sha" ]] || fail_input "no SHA to judge: neither \$SHA nor a git HEAD."
	repo="${REPO:-}"
	[[ -n "$repo" ]] || repo='{owner}/{repo}'
	# `$SONAR_GATE_GH` is a test seam, not a config knob: the 404 branch below is
	# a decision, and a decision with no case is the coverage CLOUD-242 calls
	# worthless. The suite points this at a stub; nothing else ever sets it.
	gh_bin="${SONAR_GATE_GH:-gh}"

	# "THE REMOTE HAS NEVER SEEN THIS SHA" IS NOT A FAILED READING, AND THE
	# DIFFERENCE IS THE WHOLE POINT HERE. That is the ordinary state of a local
	# HEAD: `land` rebases every lap, minting a commit no analyzer has seen, and
	# `verify` judges it before the push. Reading it as "could not look" made
	# `verify` fail on a rebase — measured twice on this change's own landing
	# laps, exit 2 on 58a7407 and again on f0f2b7b.
	#
	# AUTHENTICATED, THE ANSWER IS 422, NOT 404: `{"message":"No commit found for
	# SHA: ...","status":"422"}`. The first fix here matched only 404 and still
	# failed, because the 404 came from an UNAUTHENTICATED probe — a private repo
	# answers 404 to a stranger and 422 to a member. Matching one and not the
	# other is matching the accident rather than the fact, so both are named, and
	# the message text is matched beside the code: a bare 422 is a validation
	# error like any other and must not be read as "not pushed".
	#
	# So: not-on-the-remote is "no answer yet" (3), which `verify` passes and CI
	# retries then fails on — in CI the head is pushed by construction, so it is
	# a real anomaly there. Anything else — no network, no credential, a 5xx —
	# stays 2, because a reading this gate could not take is still not a pass.
	err=$(mktemp)
	# shellcheck disable=SC2064 # $err is expanded now on purpose: the trap must
	# name this file, not whatever the variable holds when the trap fires.
	trap "rm -f '$err'" EXIT
	if ! runs=$($gh_bin api "repos/$repo/commits/$sha/check-runs?per_page=100" \
		--jq '.check_runs[]? | "\(.status)\t\(.conclusion // "-")\t\(.name)\t\(.started_at // "")\t\(.id // 0)"' 2>"$err"); then
		if grep -qiE 'HTTP 404|not found|no commit found for sha' "$err"; then
			echo "sonar-gate: $sha carries no check-runs at all — not pushed yet, or the remote has never seen it."
			exit 3
		fi
		fail_input "could not read the check-runs for $sha. A reading this gate cannot take is not a pass."
	fi
fi

# Latest run for the one name, by the ordering `checks-green` uses: ISO-8601
# sorts lexicographically so a string compare is chronological, and the
# zero-padded id breaks a tie inside one second. Where two runs cannot be
# ordered — a reading carrying neither field — the LEAST conclusive wins, so an
# unorderable pair can never read greener than the union of its rows.
verdict=$(printf '%s\n' "$runs" | awk -F'\t' -v want="$check" '
	!NF || $3 != want { next }
	{
		key = $4 "|" sprintf("%020d", $5 + 0)
		# `cancelled` ranks with `skipped`, not with a failure (CLOUD-363). A
		# cancelled run judged nothing, so an unorderable pair holding one must
		# fall to "no answer" rather than to red — the same precedence
		# `checks-green` takes, which the header above claims to mirror.
		# (No apostrophes in here: the awk program is single-quoted, and one
		# closed it mid-comment while this was being written.)
		rank = ($1 != "completed") ? 4 : (($2 == "skipped" || $2 == "cancelled") ? 3 : (($2 == "success" || $2 == "neutral") ? 1 : 2))
		if (!seen || key > bestkey || (key == bestkey && rank > bestrank)) {
			seen = 1; bestkey = key; bestrank = rank
			beststatus = $1; bestconcl = $2
		}
	}
	END { if (seen) printf "%s|%s", beststatus, bestconcl }
')

if [[ -z "$verdict" ]]; then
	echo "sonar-gate: no $check run on $sha — absent is not a verdict, and not a veto."
	exit 0
fi

IFS='|' read -r status conclusion <<<"$verdict"

if [[ "$status" != "completed" ]]; then
	echo "sonar-gate: not an answer yet on $sha — $check is $status"
	exit 3
fi

echo "$conclusion	$check"

case "$conclusion" in
success | neutral)
	echo "sonar-gate: $check is green on $sha"
	exit 0
	;;
skipped | cancelled)
	# Both spellings of "no verdict", and the word is carried so a stall can be
	# diagnosed (CLOUD-363). `cancelled` reaching the catch-all below was worse
	# here than the defect CLOUD-363 originally fixed: this gate runs INSIDE
	# `final`, and `final` is in the required roster while the analyzer
	# deliberately is not — so a cancelled analysis reds `final`, `checks-green`
	# sees an independent `final failure` with an EMPTY no-verdict bucket, and
	# the fan-in-over-cancelled-upstreams guard cannot fire on a run it cannot
	# see. `land` then re-drafts a healthy PR.
	echo "sonar-gate: not an answer yet on $sha — $check $conclusion"
	exit 3
	;;
*)
	echo "::error:: $check is $conclusion on $sha. Read the analysis on the check-run's details page and fix it locally." >&2
	exit 1
	;;
esac
