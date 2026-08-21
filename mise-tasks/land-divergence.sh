#!/usr/bin/env bash
#MISE description="Measure: how far the landing loop diverged from linear over a window (one record per divergent run; `land-divergence-assert` decides)"
#
# CLOUD-492. THIS MEASURES; IT DOES NOT DECIDE. The verdict is
# `mise run land-divergence-assert`'s, a pure function of the records below — the
# `bench`/`bench-assert` split that `nonverdict-scan`/`nonverdict-assert` also
# uses, for the same reason: a measurement needs the network and a token, a
# decision needs neither, so the decider's suite runs in the hk gate on every
# commit while this runs on a clock.
#
# ## What "linear" means, and why each metric is the one chosen
#
# The landing loop is serialised behind a lease (CLOUD-393) and an unauthorised
# matrix is stopped server-side (CLOUD-420). The claim those make is that a PR
# buys ONE CI matrix, runs it to green, and lands. Divergence from that is the
# whole signal, and it was established once by hand — ~50 paginated calls and
# throwaway jq — which is why nothing could see a step change BETWEEN two
# assessments.
#
# ## A CANCELLED RUN IS NOT WASTE, AND COUNTING THEM INVERTS THE VERDICT
#
# The finding this sensor exists to encode. Measured 2026-08-12 after
# serialisation: 5 green CI runs against 5 cancelled, which reads as a 50%
# discard rate and is the opposite. Those cancels had p50 lifetime ~20s —
# `ci-lease-precondition` killing an unauthorised matrix for ~20 runner-seconds
# instead of billing ~500:
#
#   21:52:07  cancelled  cloud-sequential-prs   13s   <- unauthorised, killed
#   21:52:10  success    cloud-sequential-prs  432s   <- holder, runs to green
#
# Before serialisation the same population had p75 147s and max 413s. THOSE were
# waste. So the graded quantity is CANCEL LATENCY, never cancel count: a sensor
# counting cancels would score the working precondition as a defect and argue for
# removing it.
#
# ## Per workflow, never the global run list
#
# `actions/runs` carries ~3100 skipped auto-land runs a day, and at that
# insertion rate page boundaries shift mid-walk, so a paginated read of it is not
# stable. Per-workflow with a `created>=` filter is ~3-4 pages each and stable.
# (CLOUD-493 removes most of that noise at the source; this stays per-workflow
# regardless, because stability is the reason and it does not depend on volume.)
#
# ## NO WATERMARK, AND THAT IS THE DESIGN
#
# The obvious shape is a persisted ledger advanced by a watermark. It cannot work
# here: a scheduled tick gets a fresh checkout, so nothing survives between them,
# and a committed ledger pollutes the tree against non-negotiable rule 7. The
# Actions API is already the durable store (90-day retention), so every tick is a
# PURE FUNCTION OF ITS WINDOW — which also makes this re-runnable over any past
# window for free, and that is what a divergence investigation needs and a
# dashboard does not.
#
# The ETag cache below is a different thing and must not be confused with one: it
# is a within-clone read optimisation, discarded with the clone, exactly as
# `nonverdict-scan` describes its own.
#
# OUTPUT IS A POINTER, NEVER A PAYLOAD (rule 4): run ids, branch names,
# conclusions, latencies and counts. No log body, no commit message, no PR title
# is ever fetched, so none can leak. TAB-separated, because branch names are
# unconstrained.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The window, as an ISO-8601 instant. A DATE RANGE rather than a run count, which
# is the opposite of `nonverdict-scan`'s choice and deliberately so: that sensor
# asks "how often does this failure mode occur", which a fixed sample answers,
# while this one asks "what did the loop cost over a period", which only a period
# answers. A count would silently narrow the window whenever the fleet got busy —
# exactly when the answer matters most.
SINCE="${BATTEN_DIVERGENCE_SINCE:-$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)}"

# The cache root. Under `.git/`, so it is out of tree, never committed, and
# discarded with the clone rather than surviving as stale state on a fresh one.
cache="${BATTEN_DIVERGENCE_CACHE:-$(git rev-parse --git-dir)/batten-divergence}"
mkdir -p "$cache"

unreadable=0

# `gh api -i`, then the status line and the ETag out of the headers, then the
# body after the first blank line — `main-watch`'s form, as `nonverdict-scan`
# carries it. A non-2xx makes `gh` exit non-zero (a 304 included), so the call is
# guarded rather than trusted: under `set -e` an unguarded 304 would abort on the
# cheapest possible response.
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

	# Reassigned only when non-empty: a response carrying no ETag must not clear
	# the stored one, or the next tick is a cold read for no reason. `if`, not a
	# `&&` list — under `set -e` a failing trailing `&&` aborts the whole scan,
	# which `nonverdict-scan` measured as a silent empty window.
	new_etag=$(printf '%s' "$resp" | sed -n 's/^[Ee][Tt]ag: //p' | head -n1)
	if [ -n "$new_etag" ]; then
		printf '%s' "$new_etag" >"$etag_file"
	fi

	if [ "$status" = "304" ]; then
		# The whole point of the cache. No body arrives, so the previous reading
		# IS the answer; without one there is nothing to fall back to, and an
		# empty parse would read as a clean window — the false green this sensor
		# exists to report.
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

summary() {
	printf 'window\tsince=%s\tlandings=%s\tgraded=%s\tgreen=%s\tred=%s\tcancelled=%s\tcancel_p50=%s\tpeak_concurrency=%s\tqueue_p90=%s\tqueue_job_p90=%s\tretries=%s\tff_refused=%s\tff_success=%s\tunreadable=%s\n' \
		"$SINCE" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" "$unreadable"
}

bail() {
	echo "::error:: land-divergence: $1" >&2
	unreadable=$((unreadable + 1))
	summary 0 0 0 0 0 0 0 0 0 0 0 0
	exit 0
}

# `created>=` must be URL-encoded: `>` is not legal in a query string, and gh
# passes the path through verbatim.
enc_since=$(printf '%s' "$SINCE" | sed 's/:/%3A/g')

# --- CI runs over the window --------------------------------------------------
#
# `ci.yml` is the matrix a landing buys. `?created=>=` plus a per-page cap, and
# the walk stops at the first page shorter than the cap — the `link` header is
# the correct general answer, but a per-workflow day window is a few pages and
# this keeps the request parameters identical between ticks, which is what keeps
# the 304 hit rate up (`mem:github-rest-etiquette`).
# TRUNCATION IS DETECTED BY `total_count`, NOT BY RUNNING OUT OF PAGES, and that
# distinction was measured rather than reasoned.
#
# The Actions runs endpoint HARD-CAPS pagination at 1000 items while still
# reporting the true `total_count`. Measured on `fast-forward.yml` over a 25-hour
# window: `total_count` 1446, page 10 full, page 11 EMPTY. So a walk that stops
# when a page comes back short — the obvious loop, and the one written first here
# — collects 1000 of 1446 and looks exactly like a clean finish. It reported
# `ff_refused=0` over a window carrying 598 refusals, which is a perfect score
# read off a prefix: the precise false green this sensor exists to catch.
#
# `total_count` is therefore the only honest stopping condition. Compare it
# against what was actually collected and report the gap; a wrong number reported
# confidently is worse than no number, and this is the shape that produces one.
MAX_PAGES="${BATTEN_DIVERGENCE_MAX_PAGES:-10}"

walk_workflow() { # $1 = workflow file, $2 = jq expression emitting ONE line per run
	local wf="$1" expr="$2" page=1 got total="" out="" have
	while [ "$page" -le "$MAX_PAGES" ]; do
		if ! conditional_get "repos/{owner}/{repo}/actions/workflows/$wf/runs?created=%3E%3D$enc_since&per_page=100&page=$page"; then
			return 1
		fi
		if [ -z "$total" ]; then
			total=$(printf '%s' "$body" | jq -r '.total_count // 0' 2>/dev/null) || total=0
		fi
		got=$(printf '%s' "$body" | jq -r '.workflow_runs | length' 2>/dev/null) || got=0
		out="$out$(printf '%s' "$body" | jq -r "$expr" 2>/dev/null)
"
		[ "$got" = "100" ] || break
		page=$((page + 1))
	done

	out=$(printf '%s' "$out" | sed '/^[[:space:]]*$/d')
	printf '%s' "$out"
	have=$(printf '%s' "$out" | grep -c . || true)
	if [ "$have" -lt "${total:-0}" ]; then
		echo "::error:: land-divergence: read $have of $total $wf run(s) since $SINCE — the API caps this endpoint at 1000 items, so these counts describe a prefix of the window. Narrow BATTEN_DIVERGENCE_SINCE." >&2
		return 2
	fi
	return 0
}

# An exact count for one conclusion, from `total_count` with a status filter —
# one request, no pagination, and therefore no cap to be truncated by. Used
# wherever only a COUNT is needed, which is why the fast-forward ratio does not
# go through `walk_workflow` at all: at this repo's comment volume that window is
# routinely over the 1000-item ceiling, so a walk would report `could not look`
# every day for a number that is available exactly and cheaply.
count_runs() { # $1 = workflow file, $2 = status
	local n
	conditional_get "repos/{owner}/{repo}/actions/workflows/$1/runs?created=%3E%3D$enc_since&status=$2&per_page=1" || return 1
	n=$(printf '%s' "$body" | jq -r '.total_count // empty' 2>/dev/null) || return 1
	[ -n "$n" ] || return 1
	printf '%s' "$n"
}

# The per-JOB queue delay (CLOUD-501). A run's `created_at` -> `run_started_at`
# is the FIRST job's start; a matrix leg that waited behind it is invisible in
# it, and that is exactly the distinction the diagnosis needs — a wide matrix
# queueing on its own legs looks nothing like a saturated pool, and the per-run
# figure cannot tell them apart. Measured: queue p90 252s over the 13-landing
# window and 218s over the 10-landing one, against 0s over the 25-hour window
# whose idle stretch averaged it away.
#
# ONE REQUEST PER RUN, which is a real cost the header's ETag-stability argument
# cuts against — so it is bounded rather than waved at. Only GRADED runs in the
# window are read, which post-serialisation is ~1 per landing, and a run whose
# jobs cannot be read increments `unreadable` rather than being dropped.
# Dropping it would report a p90 over the legs that happened to answer, which is
# the partial-coverage false green this whole sensor exists to refuse.
#
# Pointer-only per non-negotiable 4: run id, job name, seconds. Never a log body.
job_queue() { # $1 = run id — emits `<seconds>\t<job name>`, one line per job
	conditional_get "repos/{owner}/{repo}/actions/runs/$1/jobs?per_page=100" || return 1
	printf '%s' "$body" | jq -r '
		.jobs[]? | select(.created_at != null and .started_at != null)
		| [.created_at, .started_at, (.name // "-")] | @tsv' 2>/dev/null |
		while IFS=$'\t' read -r created started name; do
			c=$(date -u -d "$created" +%s 2>/dev/null) || continue
			s=$(date -u -d "$started" +%s 2>/dev/null) || continue
			printf '%s\t%s\n' "$((s - c))" "$name"
		done
}

ci_runs=$(walk_workflow ci.yml '
	.workflow_runs[]?
	| [(.id|tostring), (.head_branch // "-"), (.conclusion // .status // "-"),
	   (.created_at // ""), (.run_started_at // ""), (.updated_at // ""),
	   (.run_attempt // 1 | tostring)]
	| @tsv') || case $? in
1) bail "could not read the CI run window, so this window judged nothing." ;;
2) unreadable=$((unreadable + 1)) ;;
esac

# --- fast-forward runs: the refusal:success ratio ------------------------------
#
# The landing bot's verdict, and CLOUD-393's baseline metric (243 refusals to 5
# merges in a half hour, before serialisation). `skipped` is not a refusal — it
# is every issue comment in the repository that was not `/fast-forward`.
ff_refused=$(count_runs fast-forward.yml failure) || {
	ff_refused=0
	unreadable=$((unreadable + 1))
}
ff_success=$(count_runs fast-forward.yml success) || {
	ff_success=0
	unreadable=$((unreadable + 1))
}

# --- landings: merged PRs in the window ---------------------------------------
#
# A landing is a MERGED PR, not a commit on `main`: a landing pushes several
# commits at once, so commit timestamps cluster and counting them would inflate
# the denominator and flatter every ratio.
if ! conditional_get "repos/{owner}/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100"; then
	bail "could not read the merged-PR list, so there is no denominator and every ratio would be meaningless."
fi
landed=$(printf '%s' "$body" | jq -r --arg since "$SINCE" '
	.[]? | select(.merged_at != null and .merged_at >= $since)
	| [(.number|tostring), (.head.ref // "-"), .merged_at] | @tsv' 2>/dev/null) || landed=""
landed=$(printf '%s' "$landed" | sed '/^[[:space:]]*$/d')
landings=$(printf '%s' "$landed" | grep -c . || true)

# --- per-PR attribution -------------------------------------------------------
#
# Runs are joined to a landing by branch AND bounded by `merged_at`, so a
# branch's post-merge runs — and a reused branch name's later life — are not
# attributed to it. A `skipped` run is a draft-era push: it spends no matrix and
# is not graded, so it is deliberately not counted.
records=""
graded=0
green=0
red=0
cancelled=0
while IFS=$'\t' read -r pr branch merged; do
	[ -n "$pr" ] || continue
	counts=$(awk -F'\t' -v b="$branch" -v m="$merged" '
		$2 == b && $4 <= m && $3 != "skipped" {
			g++
			if ($3 == "success") s++
			else if ($3 == "failure") f++
			else if ($3 == "cancelled") c++
		}
		END { printf "%d\t%d\t%d\t%d", g, s, f, c }
	' <<<"$ci_runs")
	IFS=$'\t' read -r g s f c <<<"$counts"
	graded=$((graded + g))
	green=$((green + s))
	red=$((red + f))
	cancelled=$((cancelled + c))
	# Only a PR that diverged earns a record. One graded green run is the ideal
	# and says nothing a reader needs.
	if [ "$g" -gt 1 ] || [ "$f" -gt 0 ]; then
		records="${records}pr"$'\t'"number=$pr"$'\t'"branch=$branch"$'\t'"graded=$g"$'\t'"green=$s"$'\t'"red=$f"$'\t'"cancelled=$c"$'\n'
	fi
done <<<"$landed"

# --- cancel latency, peak concurrency, queue delay, retries -------------------
#
# Latency, not count — see the header. A cancel at ~20s is the lease precondition
# working; one at 400s is a matrix billed for a verdict nobody reads.
cancel_lat=$(awk -F'\t' '
	$3 == "cancelled" && $5 != "" && $6 != "" { print }
' <<<"$ci_runs" | while IFS=$'\t' read -r id branch _conc _created started updated _attempt; do
	s=$(date -u -d "$started" +%s 2>/dev/null) || continue
	u=$(date -u -d "$updated" +%s 2>/dev/null) || continue
	printf '%s\t%s\t%s\n' "$((u - s))" "$id" "$branch"
done | LC_ALL=C sort -n)

while IFS=$'\t' read -r lat id branch; do
	[ -n "$lat" ] || continue
	records="${records}cancel"$'\t'"run=$id"$'\t'"branch=$branch"$'\t'"latency=$lat"$'\n'
done <<<"$cancel_lat"

pct() { # stream of sorted numbers on stdin, percentile as $1
	awk -v p="$1" '{ v[n++] = $1 } END { if (n == 0) { print 0; exit } i = int((n - 1) * p / 100); print v[i] }'
}
cancel_p50=$(cut -f1 <<<"$cancel_lat" | sed '/^$/d' | pct 50)

# Queue delay: created -> run_started. Zero on a healthy runner pool; a non-zero
# p90 is the fleet waiting for capacity, which is a different defect from any
# amount of contention and must not be read as one.
queue_p90=$(awk -F'\t' '$4 != "" && $5 != "" && $3 != "skipped" { print $4 "\t" $5 }' <<<"$ci_runs" |
	while IFS=$'\t' read -r created started; do
		c=$(date -u -d "$created" +%s 2>/dev/null) || continue
		s=$(date -u -d "$started" +%s 2>/dev/null) || continue
		printf '%s\n' "$((s - c))"
	done | LC_ALL=C sort -n | pct 90)

# The same delay attributed PER JOB (CLOUD-501). Read only for graded runs in
# the window — the bound `job_queue`'s header states — and a run whose jobs are
# unreadable is counted as such rather than silently contributing nothing.
job_lat=""
while IFS=$'\t' read -r id _branch; do
	[ -n "$id" ] || continue
	if ! out=$(job_queue "$id"); then
		unreadable=$((unreadable + 1))
		continue
	fi
	while IFS=$'\t' read -r secs name; do
		[ -n "$secs" ] || continue
		job_lat="${job_lat}${secs}"$'\t'"$id"$'\t'"$name"$'\n'
	done <<<"$out"
done <<<"$(awk -F'\t' '$3 != "skipped" && $3 != "-" { print $1 "\t" $2 }' <<<"$ci_runs")"

job_lat=$(printf '%s' "$job_lat" | sed '/^[[:space:]]*$/d')
# `pct` takes an ALREADY-SORTED stream, so this needs its own sort rather than
# inheriting one from the walk above.
queue_job_p90=$(cut -f1 <<<"$job_lat" | sed '/^$/d' | LC_ALL=C sort -n | pct 90)

# A `job` record only where the leg actually waited: a zero-wait leg is the ideal
# and says nothing a reader needs, which is the rule the `pr` records already use.
while IFS=$'\t' read -r secs id name; do
	[ -n "$secs" ] || continue
	[ "$secs" -gt 0 ] || continue
	records="${records}job"$'\t'"run=$id"$'\t'"job=$name"$'\t'"queue=$secs"$'\n'
done <<<"$job_lat"

# Peak concurrency: a sweep over start/end events. This is the metric that caught
# serialisation working — 25 concurrent matrices before the lease, 3 after.
peak=$(awk -F'\t' '$3 != "skipped" && $5 != "" && $6 != "" { print $5 "\t" $6 }' <<<"$ci_runs" |
	while IFS=$'\t' read -r started updated; do
		s=$(date -u -d "$started" +%s 2>/dev/null) || continue
		u=$(date -u -d "$updated" +%s 2>/dev/null) || continue
		printf '%s\t1\n%s\t-1\n' "$s" "$u"
	done | LC_ALL=C sort -n -k1,1 -k2,2r |
	awk -F'\t' '{ cur += $2; if (cur > max) max = cur } END { print max + 0 }')

retries=$(awk -F'\t' '$7 != "" && $7 + 0 > 1' <<<"$ci_runs" | grep -c . || true)

# Records first, sorted, then the summary — byte-stable, and the decider can read
# the summary without buffering the whole stream.
if [ -n "$records" ]; then
	printf '%s' "$records" | LC_ALL=C sort
fi
summary "$landings" "$graded" "$green" "$red" "$cancelled" \
	"${cancel_p50:-0}" "${peak:-0}" "${queue_p90:-0}" "${queue_job_p90:-0}" \
	"$retries" "$ff_refused" "$ff_success"
