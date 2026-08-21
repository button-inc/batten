#!/usr/bin/env bash
#MISE description="Measure: which recent CI job failures never reached a verdict (one record per failure, byte-stable; `nonverdict-assert` decides)"
#
# CLOUD-484. THIS MEASURES; IT DOES NOT DECIDE. The verdict is
# `mise run nonverdict-assert`'s, a pure function of the records below — the
# `bench`/`bench-assert` split, for the same reason: a measurement needs the network
# and a token, a decision needs neither, so the decider's suite runs in the hk gate
# on every commit while this runs on a clock.
#
# ## The predicate, and why it is CLOSED
#
# CI runs this repo's work through the pinned toolchain and nothing else runs it,
# which `mise run ci-local-parity` gates ("every task CI runs is one `verify`
# runs"). So:
#
#   a failed job rendered a VERDICT iff one of its failed steps is named
#   `Run mise run <task>` or `Run mise exec -- <command>`; otherwise it failed
#   WITHOUT reaching a verdict.
#
# `mise exec` IS THE SECOND SPELLING, added after the first cost four jobs in one
# lap (CLOUD-113). This read `Run mise run <task>` alone, on the stated premise
# that it is the only way our work reaches a runner — and the `windows` job broke
# that premise for a measured reason: its task body is bash, so `mise run` puts
# Git Bash between the runner and cargo, MSYS rewrites PATH across that boundary,
# and the toolchain the preflight just resolved is invisible three processes down.
# It runs `mise exec -- cargo test --workspace` instead, which the job's own
# comment justifies at length.
#
# The consequence nobody costed: seven genuinely failing tests then classified as
# a PROVISIONING TRANSIENT, so `land` re-ran the job four times, absorbed four
# real verdicts, and reported "the provisioning path is broken" about a suite that
# was reproducibly red. A predicate whose premise has gone false does not fail
# loudly — it answers confidently and wrongly, in the direction that spends money.
#
# Still CLOSED, which is the property that mattered: this names the two ways a
# verdict is rendered, not the growing set of ways a prelude can fail.
#
# Verified against run 31637905084, whose steps are exactly:
#
#   1 Set up job / 2 Landing lease precondition
#   3 Run actions/checkout@3d3c42e… / 4 Run jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654
#   5 Run mise run commit-lint          <- the only verdict-bearing step
#   10 Post Run actions/checkout@… / 11 Complete job
#
# The obvious alternative — a declared allowlist of prelude steps (checkout,
# mise-action, cache) — is an OPEN set: it needs an edit every time a setup action
# is added, and a forgotten edit reads a real provisioning failure as a verdict.
# Naming the verdict instead is closed, and rests on an invariant a gate holds.
#
# ## Two exclusions that are part of the predicate, not caveats
#
# * THE `final` FAN-IN. Its failure is manufactured by its siblings: run
#   31637881076 concluded `cancelled` overall while `final` concluded `failure`
#   with its only failed step `Assert all required jobs passed` — a bare `run:`
#   step, not a `mise run` one. Counted naively, `final` would read as a
#   non-verdict failure on EVERY genuinely red branch. `checks-green` guards the
#   same shape by testing no-answer before red (CLOUD-334, CLOUD-351).
# * RUNS CONCLUDED `cancelled`. That is the landing lease declining an
#   unauthorised branch (CLOUD-420), which is CLOUD-470's category. Counting it
#   here would double-count a case that already has an owner. The `?status=failure`
#   query excludes them, and `skip_run` re-checks rather than trusting the filter.
#
# ## Conditional reads, and the one place this EXTENDS ci-wait
#
# `ci-wait` keeps its ETag in a shell scalar for ONE url, alive only for the
# lifetime of one poll. Neither property survives here: a window over N runs is N
# urls, and a scheduled tick is a new process every time — so an in-memory ETag
# would make every tick a cold read and "a quiet tick costs no rate limit" false.
# The store is therefore a MAP KEYED BY URL, PERSISTED between runs, the
# out-of-tree posture `epoch.rs`'s cache and the `.git/batten-*` receipts use.
#
# A 304 KEEPS THE PREVIOUS READING, which is why the body is cached beside the
# ETag. `mem:github-rest-etiquette` is explicit that re-parsing an empty 304 body
# reads as "nothing found", and that the failure then shows up only as unexplained
# slowness. A 304 with no cached body is `unreadable`, never an empty window.
#
# Requests are SERIAL, never concurrent: secondary rate limits are about shape.
#
# OUTPUT IS A POINTER, NEVER A PAYLOAD (rule 4): run ids, job names, step names and
# counts. No log body is ever fetched, so none can leak. TAB-separated, because job
# and step names carry spaces and a space-separated key=value stream cannot hold
# them.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# How many recent failed runs to look at. A count, and deliberately not a date
# range: a window of runs is stable to re-read and cannot silently widen when the
# repo gets busier.
WINDOW="${BATTEN_NONVERDICT_WINDOW:-30}"

# The cache root. Under `.git/`, so it is out of tree, never committed, and
# discarded with the clone rather than surviving as stale state on a fresh one.
cache="${BATTEN_NONVERDICT_CACHE:-$(git rev-parse --git-dir)/batten-nonverdict}"
mkdir -p "$cache"

# `gh api -i`, then the status line and the ETag out of the headers, then the body
# after the first blank line — `main-watch`'s form. A non-2xx makes `gh` exit
# non-zero (a 304 included), so the call is guarded rather than trusted: under
# `set -e` an unguarded 304 would abort the scan on the cheapest possible response.
#
# Sets `body` and returns 0 on a usable reading, 1 when it could not look.
conditional_get() {
	local url="$1" key etag_file body_file resp status new_etag
	key=$(printf '%s' "$url" | sha1sum | cut -d' ' -f1)
	etag_file="$cache/$key.etag"
	body_file="$cache/$key.body"

	local args=(-i "$url")
	if [ -s "$etag_file" ]; then
		args+=(-H "If-None-Match: $(cat "$etag_file")")
	fi

	resp=$(gh api "${args[@]}" 2>/dev/null | tr -d '\r') || true
	status=$(printf '%s' "$resp" | sed -n '1s@^HTTP/[0-9.]* \([0-9]*\).*@\1@p')

	# Reassigned only when non-empty: a response that carries no ETag must not
	# clear the stored one, or the next tick is a cold read for no reason.
	#
	# `if`, not `[ -n … ] && …`: under `set -e` a trailing `&&` list that fails is
	# a non-zero command mid-function, which aborts the whole scan. Measured — the
	# first version exited silently with no records and no summary whenever a
	# response carried no ETag, which is indistinguishable from a clean empty
	# window and is exactly the false green this sensor exists to report.
	new_etag=$(printf '%s' "$resp" | sed -n 's/^[Ee][Tt]ag: //p' | head -n1)
	if [ -n "$new_etag" ]; then
		printf '%s' "$new_etag" >"$etag_file"
	fi

	if [ "$status" = "304" ]; then
		# The whole point of the cache. No body arrives, so the previous reading
		# IS the answer; without one there is nothing to fall back to.
		[ -s "$body_file" ] || return 1
		body=$(cat "$body_file")
		return 0
	fi

	case "$status" in
	2*) ;;
	*) return 1 ;;
	esac

	body=$(printf '%s' "$resp" | awk 'body {print} /^$/ {body=1}')
	[ -n "${body//[[:space:]]/}" ] || return 1
	printf '%s' "$body" >"$body_file"
	return 0
}

# THE POPULATION IS THE REQUIRED ROSTER, and getting this wrong was measured
# rather than reasoned. The first version judged every failed job in every
# workflow, and 22 of its 24 hits were `fast-forward` jobs failing at
# `Run sequoia-pgp/fast-forward@ea7628b…` — the merge bot DECLINING a branch that is no
# longer a descendant, which is the landing loop working exactly as designed. A
# sensor whose signal is 90% expected refusals is a sensor nobody reads.
#
# Scoping by workflow FILE would have been the obvious fix and is wrong: `ci`,
# `cross`, `darwin-link`, `msrv`, `semver` and `final` live in `ci.yml`, but
# `commit-lint`, `zizmor` and `action` do not — and `commit-lint` is the job that
# carried the CLOUD-404 503. Filtering by path would have dropped the motivating
# case.
#
# So the population is `$CI_REQUIRED_CHECKS`, the one roster `ci-wait` and `land`'s
# `graded_runs` already share (`mise.toml [env]`). A third reader of that value is
# what the value is for; a private copy here is the drift CLOUD-327 cost.
REQUIRED="${CI_REQUIRED_CHECKS:-}"
if [ -z "${REQUIRED//[[:space:]]/}" ]; then
	echo "::error:: nonverdict-scan: CI_REQUIRED_CHECKS is empty — without the roster this cannot tell a required job from an unrelated one, and a count over all of them is meaningless. Run through \`mise run\` so mise.toml's [env] applies." >&2
	printf 'window\truns=0\tfailed_jobs=0\tnonverdict=0\tverdict=0\tunreadable=1\n'
	exit 0
fi

# The fan-in, excluded by name: its failure is manufactured by its siblings.
FAN_IN="final"

unreadable=0
runs_seen=0
records=""

# SINGLE-RUN MODE (CLOUD-483). `land` asks the same question about ONE concluded
# run, on its red-CI stop path, to tell a provisioning transient from a verdict.
# It is a mode rather than a second task because the classification must exist
# once: two readers deciding "did this job reach a verdict" from two copies of the
# jq is the CLOUD-351 shape, and the copy that drifts is the one nobody runs on a
# clock.
#
# It emits RECORDS ONLY, no `window` summary — there is no window to summarise,
# and a caller testing "every record is nonverdict" must not have to special-case
# a trailing line that is neither. An empty stream is therefore unambiguous: no
# failed required job was classifiable, which is "could not look" and never
# "nothing was wrong".
one_run=""
if [ "${1:-}" = "--run" ]; then
	one_run="${2:-}"
	if [ -z "${one_run//[[:space:]]/}" ]; then
		echo "::error:: nonverdict-scan: --run needs a run id. Without one there is nothing to classify, and an empty record stream would read as 'no failed job reached a verdict'." >&2
		exit 2
	fi
fi

if [ -n "$one_run" ]; then
	run_ids="$one_run"
elif ! conditional_get "repos/{owner}/{repo}/actions/runs?status=failure&per_page=$WINDOW"; then
	echo "::error:: nonverdict-scan: could not read the run list, so this window judged nothing." >&2
	printf 'window\truns=0\tfailed_jobs=0\tnonverdict=0\tverdict=0\tunreadable=1\n'
	exit 0
else
	# `.id` and `.conclusion` only. Sorted by id so the record stream is byte-stable
	# across ticks that see the same window in a different order.
	run_ids=$(printf '%s' "$body" | jq -r '[.workflow_runs[]? | select(.conclusion == "failure") | .id] | sort | .[]' 2>/dev/null) || run_ids=""
fi

failed_jobs=0
nonverdict=0
verdict=0

while IFS= read -r run; do
	[ -n "$run" ] || continue
	runs_seen=$((runs_seen + 1))

	if ! conditional_get "repos/{owner}/{repo}/actions/runs/$run/jobs?per_page=100"; then
		unreadable=$((unreadable + 1))
		continue
	fi

	# One line per failed job: the job name, then whether any FAILED step is a
	# `Run mise run …` step. The classification is done in jq over the payload
	# rather than in shell over a rendered string, so a job name containing a tab
	# cannot forge a field.
	while IFS=$'\t' read -r job kind step; do
		[ -n "$job" ] || continue
		failed_jobs=$((failed_jobs + 1))
		if [ "$kind" = "verdict" ]; then
			verdict=$((verdict + 1))
		else
			nonverdict=$((nonverdict + 1))
		fi
		records="${records}${kind}"$'\t'"run=$run"$'\t'"job=$job"$'\t'"step=$step"$'\n'
	done <<<"$(
		printf '%s' "$body" | jq -r --arg fan "$FAN_IN" --arg required "$REQUIRED" '
			($required | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $roster
			| [.jobs[]?
			   | select(.conclusion == "failure")
			   | select(.name != $fan)
			   | select([.name] | inside($roster))]
			| sort_by(.name)
			| .[]
			| . as $job
			| ([$job.steps[]? | select(.conclusion == "failure")] | sort_by(.number)) as $failed
			| ([$failed[] | select(.name | startswith("Run mise run ") or startswith("Run mise exec -- "))] | first) as $task
			| if $task
			  then [$job.name, "verdict", $task.name]
			  else [$job.name, "nonverdict", (($failed | first | .name) // "unknown")]
			  end
			| @tsv
		' 2>/dev/null
	)"
done <<<"$run_ids"

# Records first, sorted, then the summary — so the stream is byte-stable and the
# decider can read the summary without buffering the whole thing.
if [ -n "$records" ]; then
	printf '%s' "$records" | LC_ALL=C sort
fi
# No summary in single-run mode: there is no window, and a caller asking "is every
# record a nonverdict" must not have to discount a trailing line that is neither.
if [ -z "$one_run" ]; then
	printf 'window\truns=%s\tfailed_jobs=%s\tnonverdict=%s\tverdict=%s\tunreadable=%s\n' \
		"$runs_seen" "$failed_jobs" "$nonverdict" "$verdict" "$unreadable"
fi
