#!/usr/bin/env bash
#MISE description="Gate: may the release PR land now? Debounce — 30 quiet minutes on main, or 24h since the last release, whichever comes first"
#
# Releases fired once per crate-touching commit: 57 tags, most of them one or two
# commits apart. Nothing in the pipeline throttled — every `concurrency` group is
# a constant or keyed per-SHA/per-tag with `cancel-in-progress: false`, so runs
# serialize but never coalesce. N pushes to `main` meant N tags, N
# `fast-forward` runs, and N seven-leg `release-artifacts` matrices.
#
# THE RELEASE PR IS ALREADY THE ACCUMULATOR, which is why nothing about cutting a
# release changes here. release-plz rewrites the `release-plz-*` PR with every
# commit since the last tag at no cost; what happened too often is *landing* it.
# So the debounce is one predicate on one edge — `auto-release-land.yml`'s
# automated `/fast-forward` — and this task is that predicate.
#
# IT IS AN OR, NOT AN AND. Fast releases are good, so the ordinary path is a
# trailing-edge debounce: land once `main` has been still for QUIET minutes, which
# on a normal day is a few minutes after a working session wraps. The second term
# is the max-wait that stops a busy repo from starving the release: once the last
# release is MAX_WAIT old, land regardless of how busy `main` is. Requiring both
# would invert the intent — a repo that never goes quiet would never ship.
#
#   due  <=>  minutes since the last commit on main >= QUIET (30)
#              OR hours since the last release      >= MAX_WAIT (24)
#              OR there is no release yet
#
# QUIET IS MEASURED ON `main` ONLY. The `release-plz-*` branch is pushed every
# time the PR is refreshed — that is the debounce observing its own input, and
# counting it would reset the window on the very event it exists to absorb. Any
# push to `main` resets it, including one that touches nothing under `crates/`
# and therefore cuts no release at all (`mem:workflow/board-states`: the path is
# the predictor, not the commit type). That over-counts, and deliberately: the
# cost is one extra quiet window, and the alternative is this gate re-deriving
# release-plz's own "did the version change" judgement from the file list.
#
# Exit 0 due / 1 holding / 2 could-not-look. The hold reason goes to STDOUT, not
# stderr, and carries no `::error::`: holding is the ordinary outcome on most
# ticks, and annotating it would paint a working debounce red in the Actions UI
# every half hour. Only exit 2 — a knob that does not parse, a timestamp that
# does not parse, an API that would not answer — is an error, because that is the
# case where the gate did not decide anything.
#
# Both readings are injectable (`RELEASE_DUE_NOW`, `RELEASE_DUE_LAST_ACTIVITY`,
# `RELEASE_DUE_LAST_RELEASE`), and with them set this makes no network call at
# all — which is what lets `tests/release-due.bats` cover every branch offline,
# including the two boundaries, without a stub for `gh`.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT busy-main-is-due|s/^exit 1$/exit 0/|a busy main inside the max wait holds

set -euo pipefail

QUIET_MINUTES="${RELEASE_QUIET_MINUTES:-30}"
MAX_WAIT_HOURS="${RELEASE_MAX_WAIT_HOURS:-24}"

fail_input() {
	echo "::error:: release-due: $*" >&2
	exit 2
}

# A knob that does not parse is exit 2, never a silent fall back to the default:
# a typo'd window would otherwise read as a working debounce set to something
# nobody chose.
case "$QUIET_MINUTES" in
'' | *[!0-9]*) fail_input "RELEASE_QUIET_MINUTES must be a whole number of minutes, got '$QUIET_MINUTES'." ;;
esac
case "$MAX_WAIT_HOURS" in
'' | *[!0-9]*) fail_input "RELEASE_MAX_WAIT_HOURS must be a whole number of hours, got '$MAX_WAIT_HOURS'." ;;
esac

# `date -d` parses the RFC3339 stamps GitHub returns. It reports failure by exit
# code rather than calling `fail_input` itself: this is only ever used in a
# command substitution, and an `exit` there ends the subshell, not the run — the
# gate would carry on with an empty reading. Every call site pairs it with `||`.
epoch() {
	date -d "$1" +%s 2>/dev/null
}

# Injected readings are checked with `${VAR+set}` rather than emptiness, so an
# explicit empty RELEASE_DUE_LAST_RELEASE means "no release exists yet" — a real
# state, and one of the three due-paths — instead of falling through to the API.
if [[ -n "${RELEASE_DUE_NOW+set}" ]]; then
	now=$(epoch "$RELEASE_DUE_NOW") || fail_input "cannot parse RELEASE_DUE_NOW '$RELEASE_DUE_NOW'."
else
	now=$(date -u +%s)
fi

if [[ -n "${RELEASE_DUE_LAST_ACTIVITY+set}" ]]; then
	activity_raw="$RELEASE_DUE_LAST_ACTIVITY"
else
	activity_raw=$(gh api "repos/{owner}/{repo}/commits/main" --jq '.commit.committer.date' 2>/dev/null) ||
		fail_input "could not read the last commit on main. A reading this gate cannot take is not a pass."
fi
[[ -n "$activity_raw" ]] || fail_input "the last commit on main has no timestamp."

# The list endpoint rather than `releases/latest`: an empty array is a repo with
# no release yet, answered with a 200, so "nothing released" stays distinguishable
# from "could not look" without special-casing a 404.
if [[ -n "${RELEASE_DUE_LAST_RELEASE+set}" ]]; then
	release_raw="$RELEASE_DUE_LAST_RELEASE"
else
	release_raw=$(gh api "repos/{owner}/{repo}/releases?per_page=1" --jq '.[0].published_at // ""' 2>/dev/null) ||
		fail_input "could not read the latest release. A reading this gate cannot take is not a pass."
fi

activity_at=$(epoch "$activity_raw") || fail_input "cannot parse the last-commit timestamp '$activity_raw'."
activity_age=$((now - activity_at))
quiet_window=$((QUIET_MINUTES * 60))

# No release yet: there is no interval to wait out, and holding would mean the
# first release of a repo can never be cut by this path.
if [[ -z "$release_raw" ]]; then
	echo "release-due: due — no release exists yet, so there is no interval to wait out."
	exit 0
fi

release_at=$(epoch "$release_raw") || fail_input "cannot parse the last-release timestamp '$release_raw'."
release_age=$((now - release_at))
max_wait_window=$((MAX_WAIT_HOURS * 3600))

# Max-wait is checked first so its reason is the one reported when both hold: it
# is the term that overrode a busy `main`, and that is the more surprising
# release to explain after the fact.
if [[ "$release_age" -ge "$max_wait_window" ]]; then
	echo "release-due: due — last release was $((release_age / 60))m ago, at or past the ${MAX_WAIT_HOURS}h max wait."
	exit 0
fi

if [[ "$activity_age" -ge "$quiet_window" ]]; then
	echo "release-due: due — main has been quiet for $((activity_age / 60))m, at or past the ${QUIET_MINUTES}m window."
	exit 0
fi

echo "release-due: holding — main moved $((activity_age / 60))m ago (quiet window ${QUIET_MINUTES}m) and the last release was $((release_age / 60))m ago (max wait ${MAX_WAIT_HOURS}h). The release PR stays open and keeps accumulating; a maintainer commenting /fast-forward lands it now."
exit 1
