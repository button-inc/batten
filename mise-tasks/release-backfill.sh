#!/usr/bin/env bash
#MISE description="Record historical tags in the Linear release pipeline: dispatch the backfill workflow once per tag, oldest first, stopping on the first failure"
#
# CLOUD-618. Fixing the release path makes the NEXT tag record. It reaches no tag
# that already shipped, and there were 111 of them against a pipeline holding 0
# releases (measured 2026-08-23) — so a release record that starts at v0.0.111
# answers "what shipped" from the wrong end of the history.
#
# `.github/workflows/linear-release-backfill.yml` records ONE tag. This is the
# sweep over the rest, and it exists rather than being a loop somebody types
# because the repeated part is the part that goes wrong: 111 dispatches by hand
# is 111 chances to skip one, repeat one, or run them in an order that makes the
# commit ranges wrong.
#
# NOT A GATE. It decides nothing about the tree and has no exit-code contract to
# uphold beyond "the sweep finished or it did not"; the shape of the workflow it
# dispatches is `release-tracking-check`'s business. Its description deliberately
# does not open with `Gate`, which is what `mutant-census` keys on.
#
# ─── OLDEST FIRST, AND SERIALLY ──────────────────────────────────────────────
#
# The action derives a release's attached issues from the tag's COMMIT RANGE, so
# the order is load-bearing rather than tidy: a sweep that recorded v0.0.110
# before v0.0.78 would be asking for ranges relative to a pipeline state that
# does not exist yet. `sort -V` puts them in version order, and the workflow's
# own `concurrency` group — keyed by workflow, deliberately NOT by tag — is what
# keeps two of them from overlapping on the runner.
#
# ─── STOP ON THE FIRST FAILURE ───────────────────────────────────────────────
#
# The alternative was measured before it was written: CLOUD-750 recorded
# `LINEAR_ACCESS_KEY` refused HTTP 401 by the tracker's API under both auth
# forms. If the action refuses it too, a sweep that pressed on would queue 110
# more doomed runs and bury the one line that says why. Stopping leaves the
# remainder unrecorded, which is recoverable: `sync` is create-or-update, so
# re-running a tag already recorded is a no-op and the sweep is resumable from
# wherever it stopped.
#
# ─── WHY IT WAITS RATHER THAN FIRING AND FORGETTING ──────────────────────────
#
# A dispatch that returns 0 means GitHub accepted the request, not that the run
# succeeded — that is exactly the "green while doing nothing" shape this whole
# issue is about, one layer out. So each tag is waited on, and the wait has a real
# exit condition rather than a clock: the newest run id for this workflow is read
# BEFORE the dispatch, and the loop waits for a DIFFERENT id to appear and then
# for that run to complete. Without the before-reading, the first poll would find
# the previous tag's already-completed run and report it as this tag's success.
#
# The attempt cap is a runaway backstop on the COUNT, in the sense
# `LAND_MAX_LAPS` is: a dispatched run that never appears is a platform failure,
# not a slow one, and a sweep that hangs forever reports nothing at all.
set -euo pipefail

WORKFLOW="${RELEASE_BACKFILL_WORKFLOW:-linear-release-backfill.yml}"
# The `<TASK>_GH` indirection `attestation-check` and `sonar-gate` already use, so
# the suite can drive a stub without touching PATH.
GH_BIN="${RELEASE_BACKFILL_GH:-gh}"
POLL_INTERVAL="${RELEASE_BACKFILL_POLL_INTERVAL:-5}"
MAX_POLLS="${RELEASE_BACKFILL_MAX_POLLS:-240}"

dry_run=0
tags=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run)
		dry_run=1
		shift
		;;
	-*)
		echo "usage: release-backfill [--dry-run] [<tag>...]" >&2
		exit 2
		;;
	*)
		tags+=("$1")
		shift
		;;
	esac
done

# --- which tags -----------------------------------------------------------------
#
# Arguments win, then the injected list (which is what makes this suite-testable
# without a repository full of tags), then the repository's own tags. `sort -V`
# rather than `sort`: lexical order puts v0.0.110 before v0.0.78, which is the
# reverse of what the commit-range argument above needs.
if [[ "${#tags[@]}" -eq 0 ]]; then
	if [[ -n "${RELEASE_BACKFILL_TAGS:-}" ]]; then
		while IFS= read -r tag; do
			[[ -n "$tag" ]] && tags+=("$tag")
		done < <(tr ' ' '\n' <<<"$RELEASE_BACKFILL_TAGS" | sort -V)
	else
		while IFS= read -r tag; do
			[[ -n "$tag" ]] && tags+=("$tag")
		done < <(git tag --list 'v[0-9]*' | sort -V)
	fi
fi

if [[ "${#tags[@]}" -eq 0 ]]; then
	echo "::error:: release-backfill: no tags to record. Nothing here can tell an empty repository from a bad pattern, so this is a refusal rather than a clean sweep of nothing." >&2
	exit 1
fi

# A tag the repository does not carry would reach the workflow's own tag-exists
# probe and fail there, one round trip later. Refusing here costs nothing and
# names the whole bad list at once instead of the first element of it.
bad=()
for tag in "${tags[@]}"; do
	case "$tag" in
	v[0-9]*) ;;
	*) bad+=("$tag") ;;
	esac
done
if [[ "${#bad[@]}" -ne 0 ]]; then
	echo "::error:: release-backfill: ${#bad[@]} argument(s) are not release tags: ${bad[*]}" >&2
	exit 2
fi

if [[ "$dry_run" = 1 ]]; then
	echo "release-backfill: would dispatch $WORKFLOW for ${#tags[@]} tag(s), oldest first:"
	printf '  %s\n' "${tags[@]}"
	exit 0
fi

if ! command -v "$GH_BIN" >/dev/null 2>&1; then
	echo "::error:: release-backfill: no forge client at '$GH_BIN' (\$RELEASE_BACKFILL_GH overrides), so nothing can be dispatched. Run: mise install aqua:cli/cli" >&2
	exit 2
fi

# The newest run id for this workflow, or the empty string when it has never run.
# Read through `gh`'s own `--jq` rather than a pipe into `jq`: this task is
# launched by `mise run`, so a pinned `jq` is on PATH, but one dependency fewer in
# a loop that runs once per tag is worth the symmetry with `sonar-gate`.
newest_run() {
	"$GH_BIN" run list --workflow "$WORKFLOW" --limit 1 \
		--json databaseId --jq '.[0].databaseId // ""' 2>/dev/null || true
}

run_state() { # run_state <id> -> "<status> <conclusion>"
	"$GH_BIN" run view "$1" --json status,conclusion \
		--jq '"\(.status) \(.conclusion // "")"' 2>/dev/null || true
}

recorded=0
for tag in "${tags[@]}"; do
	before=$(newest_run)

	if ! "$GH_BIN" workflow run "$WORKFLOW" -f "tag=$tag" >/dev/null; then
		echo "::error:: release-backfill: the dispatch for $tag was refused, after recording $recorded tag(s). \`sync\` is create-or-update, so re-run this task once the cause is fixed — the tags already recorded cost nothing to repeat." >&2
		exit 1
	fi

	# Wait for THIS run rather than for the newest one: the previous tag's run has
	# already completed by now, so a poll that only asked "is the newest run
	# finished" would answer yes immediately and attribute its conclusion here.
	id=""
	polls=0
	while [[ -z "$id" ]]; do
		polls=$((polls + 1))
		if [[ "$polls" -gt "$MAX_POLLS" ]]; then
			echo "::error:: release-backfill: the run dispatched for $tag never appeared after $MAX_POLLS poll(s). A dispatch GitHub accepted and never scheduled is a platform failure, not a slow run; $recorded tag(s) were recorded before this." >&2
			exit 1
		fi
		candidate=$(newest_run)
		if [[ -n "$candidate" ]] && [[ "$candidate" != "$before" ]]; then
			id="$candidate"
			break
		fi
		sleep "$POLL_INTERVAL"
	done

	status=""
	conclusion=""
	while :; do
		polls=$((polls + 1))
		if [[ "$polls" -gt "$MAX_POLLS" ]]; then
			echo "::error:: release-backfill: run $id for $tag did not finish within $MAX_POLLS poll(s); $recorded tag(s) were recorded before this." >&2
			exit 1
		fi
		read -r status conclusion <<<"$(run_state "$id")"
		[[ "$status" = "completed" ]] && break
		sleep "$POLL_INTERVAL"
	done

	if [[ "$conclusion" != "success" ]]; then
		echo "::error:: release-backfill: $tag concluded '$conclusion' in run $id, so the sweep stops here with $recorded tag(s) recorded. Read that run before re-running: a credential the action refuses fails every tag identically, and pressing on would queue $((${#tags[@]} - recorded - 1)) more of them." >&2
		exit 1
	fi

	recorded=$((recorded + 1))
	echo "release-backfill: $tag recorded (run $id)"
done

echo "release-backfill: ${#tags[@]} tag(s) recorded, oldest first"
