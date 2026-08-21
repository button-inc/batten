#!/usr/bin/env bats
# subject: mise-tasks/land-divergence-assert.sh
# CLOUD-492. The deciding half: is the landing loop's divergence from linear under
# budget? A pure function of records on stdin — no network, no token — which is
# what lets it run in the hk gate on every commit while the measurement runs on a
# clock.

setup() {
	ASSERT="$BATS_TEST_DIRNAME/../mise-tasks/land-divergence-assert.sh"
}

# A `window` summary with everything at its ideal, so each case varies exactly one
# field and nothing else can explain the verdict.
window() {
	local landings="${1:-10}" graded="${2:-10}" red="${3:-0}" cancel_p50="${4:-15}" \
		peak="${5:-1}" queue="${6:-0}" ff="${7:-0}" unreadable="${8:-0}" job_queue="${9:-0}"
	printf 'window\tsince=2026-08-12T00:00:00Z\tlandings=%s\tgraded=%s\tgreen=%s\tred=%s\tcancelled=0\tcancel_p50=%s\tpeak_concurrency=%s\tqueue_p90=%s\tqueue_job_p90=%s\tretries=0\tff_refused=%s\tff_success=5\tunreadable=%s\n' \
		"$landings" "$graded" "$((graded - red))" "$red" "$cancel_p50" "$peak" "$queue" "$job_queue" "$ff" "$unreadable"
}

@test "a linear window passes: one graded run per landing, green, uncontended" {
	run "$ASSERT" <<<"$(window)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1.00 each"* ]]
}

# --- direction 1: over the ratio ---------------------------------------------

@test "graded runs per landing over budget exits 1" {
	# The headline divergence. 30 graded runs over 10 landings is 3.00 each,
	# against a budget of 2.00 — the pre-serialisation shape, measured at 6.95.
	run "$ASSERT" <<<"$(window 10 30)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"3.00 per landing"* ]]
	[[ "$output" == *"budget of 2.00"* ]]
}

@test "the ratio is reported in hundredths rather than rounded" {
	# A gate that rounds is a gate that disagrees with the number it printed.
	run "$ASSERT" <<<"$(window 64 422)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"6.59 per landing"* ]]
}

@test "red runs per landing over budget exits 1" {
	run "$ASSERT" <<<"$(window 10 10 5)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"0.50 per landing"* ]]
	[[ "$output" == *"verify\` was skipped"* ]]
}

# --- directions 3 and 4: cancel LATENCY, never cancel count -------------------

@test "a 20s cancellation does NOT count as waste" {
	# The load-bearing case. Measured post-serialisation: 5 green against 5
	# cancelled, p50 ~20s — `ci-lease-precondition` stopping an unauthorised
	# matrix for ~20 runner-seconds instead of billing ~500. A gate counting
	# cancellations would score the working mechanism as a defect and argue for
	# removing it, so the graded quantity is latency.
	run "$ASSERT" <<<"$(window 10 10 0 20)"
	[ "$status" -eq 0 ]
}

@test "a 400s cancellation DOES count as waste" {
	# The other direction, and the one that makes the metric discriminate: by
	# 400s the matrix has been paid for, so the cancellation saved nothing.
	run "$ASSERT" <<<"$(window 10 10 0 400)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"median lifetime of 400s"* ]]
}

# --- the remaining budgets ----------------------------------------------------

@test "peak concurrency above the admitted-successor bound exits 1" {
	# Landing is serialised behind a lease that admits one successor, so anything
	# above that is something spending CI without holding it. Measured 25 before
	# the lease, 3 after.
	run "$ASSERT" <<<"$(window 10 10 0 15 25)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"25 CI matrices ran concurrently"* ]]
}

@test "a queue delay is reported as its own defect, not as contention" {
	run "$ASSERT" <<<"$(window 10 10 0 15 1 300)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"runner pool saturating"* ]]
}

@test "any fast-forward refusal at all exits 1" {
	# 243:5 before the lease, 0:5 after. A refusal means the branch went behind
	# before the bot answered, so the budget is zero rather than tunable.
	run "$ASSERT" <<<"$(window 10 10 0 15 1 0 1)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"refused 1 time(s)"* ]]
}

# --- direction 2: could not look is never a pass ------------------------------

@test "a partially-read window exits 2, never 0" {
	# bench-assert's partial-coverage rule: a run that measured two of three paths
	# and reported green over the two is exactly the partial-coverage false green.
	run "$ASSERT" <<<"$(window 10 10 0 15 1 0 0 1)"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cover less than it claims"* ]]
}

@test "an unreadable window exits 2 even when every other number is ideal" {
	# The ordering matters: if the budgets were judged first, a perfect prefix of
	# a bad window would exit 0 before anything noticed it was a prefix.
	run "$ASSERT" <<<"$(window 10 10 0 15 1 0 0 3)"
	[ "$status" -eq 2 ]
}

@test "empty stdin exits 2" {
	run "$ASSERT" <<<""
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "records with no window summary exit 2" {
	run "$ASSERT" <<<"$(printf 'pr\tnumber=1\tbranch=b\tgraded=9\tgreen=9\tred=0\tcancelled=0\n')"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no \`window\` summary"* ]]
}

@test "two concatenated measurements exit 2 rather than describing neither" {
	run "$ASSERT" <<<"$(
		window
		window 10 30
	)"
	[ "$status" -eq 2 ]
	[[ "$output" == *"more than one"* ]]
}

@test "A JOB QUEUE DELAY IS ITS OWN BUDGET, over a clean per-run figure" {
	# CLOUD-501, and the case the whole per-job attribution exists for: a run's
	# `created_at` -> `run_started_at` is its FIRST job's start, so a matrix leg
	# queueing behind its siblings is invisible in it. Per-run 0s, per-job 300s is
	# a wide matrix contending with itself, and a gate reading only the run figure
	# would call that window ideal.
	run "$ASSERT" <<<"$(window 10 10 0 15 1 0 0 0 300)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"individual JOBS waited 300s"* ]]
}

@test "a clean per-job figure passes, and the success line reports it" {
	run "$ASSERT" <<<"$(window)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"per job"* ]]
}

@test "a summary missing the per-job count exits 2 rather than reading it as zero" {
	# A measurer that predates the field must not be judged as if it had reported
	# a perfect one — that is the partial-coverage false green in miniature.
	run "$ASSERT" <<<"$(printf 'window\tsince=x\tlandings=10\tgraded=10\tred=0\tcancel_p50=1\tpeak_concurrency=1\tqueue_p90=0\tff_refused=0\tunreadable=0\n')"
	[ "$status" -eq 2 ]
	[[ "$output" == *"queue_job_p90"* ]]
}

@test "a summary missing a count exits 2 rather than reading it as zero" {
	run "$ASSERT" <<<"$(printf 'window\tsince=x\tlandings=10\tgraded=10\n')"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot be judged"* ]]
}

@test "a non-numeric count exits 2" {
	run "$ASSERT" <<<"$(printf 'window\tsince=x\tlandings=lots\tgraded=10\tred=0\tcancel_p50=1\tpeak_concurrency=1\tqueue_p90=0\tqueue_job_p90=0\tff_refused=0\tunreadable=0\n')"
	[ "$status" -eq 2 ]
}

# --- anti-vacuity -------------------------------------------------------------

@test "a window with no landings passes, and says why" {
	# A gate that cannot fire must not be indistinguishable from one that found
	# nothing — and a quiet day is the honest reading here, not a defect.
	run "$ASSERT" <<<"$(window 0 0)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no landings in the window"* ]]
}

@test "the divergent PRs are named on failure, pointer-only" {
	# Rule 4: the record carries a number and a branch, never a title or a body.
	run "$ASSERT" <<<"$(
		printf 'pr\tnumber=366\tbranch=claude/landing-lease-optimization\tgraded=16\tgreen=12\tred=2\tcancelled=2\n'
		window 10 30
	)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"number=366"* ]]
	[[ "$output" == *"graded=16"* ]]
}
