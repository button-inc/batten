# CI signal: the landing loop stays linear over a window (CLOUD-492, ported under
# CLOUD-1717, and out of a consumer module into this preset under CLOUD-843).
#
# THE CLAIM BEING GRADED. A landing loop serialised behind a lease, with any
# unauthorised matrix stopped server-side, claims that a change buys ONE CI
# matrix, runs it to green, and lands. Divergence from that is the whole signal.
# Nothing here names a workflow, a job or a branch: the producer measured those
# against the consumer's own names, and what reaches this module is a window of
# counts any consumer running such a loop can hold to the same budgets.
#
# THE RECORD IS THE VERB'S, NOT THE CONSUMER'S. `batten record divergence` writes
# the `land-divergence` family under that fixed name — the family is the engine
# verb's vocabulary, the way `record closes` writes its own — so reading it by name
# names no consumer fact (non-negotiable rule 1). A consumer that never runs the
# producer has no family, and this module is silent.
#
# THE SPLIT. The producer measures and this decides, kept apart because a
# measurement needs the network and a token and a decision needs neither
# (CLOUD-1559). The pagination walk, the ETag cache, the `total_count` truncation
# guard and every instant subtraction stay in the verb: house style §5 makes
# `check` `read` and incapable of spawning, and `Fact::Instant` projects `null` to
# every module.
#
# A CANCELLED RUN IS NOT WASTE, AND COUNTING THEM INVERTS THE VERDICT. Measured
# 2026-08-12 after serialisation: 5 green CI runs against 5 cancelled, which reads
# as a 50% discard rate and is the opposite — those cancels had p50 lifetime ~20s,
# a lease precondition killing an unauthorised matrix for ~20 runner-seconds
# instead of billing ~500. So the graded quantity is CANCEL LATENCY, never cancel
# count: a rule counting cancels would score the working precondition as a defect.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, EXCEPT WHERE IT IS PARTIAL. Total blindness —
# an unreadable CI run window, an unreadable merged-PR list — is the producer
# refusing at write time and removing any stale record, which reads here as
# silence. `unreadable` is the third case and is not blindness: the producer read
# PART of its window, which is the partial-coverage false green and its own
# finding. The Actions runs endpoint hard-caps pagination at 1000 items while
# still reporting the true `total_count`; over a 25-hour window a walk that
# stopped on a short page collected 1000 of 1446 and reported `ff_refused=0` over
# a window carrying 598 refusals. A perfect score read off a prefix.
#
# EVERY NAME IS PREFIXED `lane_`: a preset's modules share one `package`, and its
# sibling binds the same shapes under `job_`. Re-binding one does not shadow.
#
# THE PATTERN IS INLINE (`rules/policy-modules.md`): a preset reaches a consumer
# who wrote no `[[pattern]]` row, so `data.batten.patterns` is undefined for it.
#MUTANT-SUITE crates/batten/tests/it/land_divergence.rs
#MUTANT lane-partial-window-passes|s@^\tlane_count_of("unreadable") > 0$@\tfalse@|land_divergence::a_partially_read_window_is_a_finding_rather_than_a_clean_one
#MUTANT lane-graded-over-budget-passes|s@^\tlane_ratio("graded") > lane_graded_budget$@\tfalse@|a_loop_buying_more_than_one_matrix_per_landing_is_reported
#MUTANT lane-torn-record-passes|s@^\tcount(lane_summaries) != 1$@\tfalse@|land_divergence::a_torn_record_is_a_finding_rather_than_a_clean_window
#MUTANT lane-refusal-budget-loosened|s@^\tlane_count_of("ff_refused") > 0$@\tfalse@|any_fast_forward_refusal_at_all_is_reported

# METADATA
# description: |
#   Bound to the TREE surface: the enabling row is `scope = "tree"`, so this
#   reads `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]

package batten.ci_signal

import rego.v1

rules contains "lane read partial"

rules contains "lane count spent"

rules contains "lane grade red"

rules contains "lane reach late"

rules contains "lease guard dropped"

rules contains "lane measure late"

rules contains "job measure late"

rules contains "branch reach stale"

# THE BUDGETS, SEEDED FROM THE MEASUREMENT rather than from an aspiration — taken
# 2026-08-12, after landing serialisation, so the gate starts at the observed state.
#
# IN THE MODULE RATHER THAN BEHIND SEVEN ENV OVERRIDES, which is `timeout-drift`'s
# and `nonverdict`'s placement and is what the port made possible: the knobs existed
# so the retired suite could point a budget at a fixture, and a module's cases vary
# the RECORD instead. Seven fewer knobs nobody was turning.

# Ratios are held in HUNDREDTHS, carried over from the decider because the numbers
# a reader has seen are in these units. The ideal is 1.00 graded runs per landing;
# the budget is 2.00, because the second run is the ~20s lease-precondition
# cancellation the same measurement showed is the mechanism WORKING.
lane_graded_budget := 200

lane_red_budget := 20

# Seconds. An early cancellation is the lease precondition working; a late one is a
# matrix billed for a verdict nobody reads.
lane_cancel_budget := 60

# Landing is serialised behind a lease, so concurrency above the admitted-successor
# bound means something is spending CI without holding it.
lane_concurrency_budget := 3

# Seconds, and the same figure for both: the ideal is that a run — and each of its
# legs — starts when it is created.
lane_queue_budget := 30

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
lane_recorded := input.tree.records["land-divergence"]

# EXACTLY ONE SUMMARY, OR THE RECORD IS TORN — AND TORN IS A FINDING. Two
# DIFFERENT summaries mean two measurements were concatenated and a count over both
# describes neither; none means the window was never closed. The retired decider
# refused both (`land-divergence-assert.sh:88-89,93-94`). The first port gated
# `fields` on exactly one summary and stopped, so all eight rules went undefined
# and a torn store read GREEN while this comment claimed the arm was kept. `torn`
# below is that arm, actually kept.
lane_summaries contains raw if {
	some raw in lane_recorded
	startswith(raw, "window\t")
}

lane_fields[pair[0]] := pair[1] if {
	count(lane_summaries) == 1
	some raw in lane_summaries
	columns := split(raw, "\t")
	some idx in numbers.range(1, count(columns) - 1)
	pair := split(columns[idx], "=")
	count(pair) == 2
}

# A COUNT THAT IS NOT A NUMBER IS NOT A ZERO. The retired decider refused rather
# than coercing (`land-divergence-assert.sh:115-116`), because a count silently
# read as zero is a clean window over input nobody parsed. Undefined alone would
# leave every rule unfired, so `torn` reads it as a refusal.
lane_count_of(key) := number if {
	raw := lane_fields[key]
	regex.match("^[0-9]+$", raw)
	number := to_number(raw)
}

# The columns some rule below decides over — every one the producer emits as a
# whole number. `since` is a timestamp and is not required to parse as one.
lane_window_columns := {
	"landings", "graded", "red", "cancel_p50", "peak_concurrency",
	"queue_p90", "queue_job_p90", "ff_refused", "unreadable",
}

# Present but untrustworthy: no summary, more than one, or one missing or
# garbling a column a rule reads. `recorded` is DEFINED in every case, which is
# what separates these from could-not-look and why they must not collapse into it.
lane_torn if {
	lane_recorded
	count(lane_summaries) != 1
}

lane_torn if {
	count(lane_summaries) == 1
	some key in lane_window_columns
	not lane_count_of(key)
}

# Per-landing, in hundredths.
#
# TRUE DIVISION WHERE THE SHELL TRUNCATED, which is a fidelity improvement rather
# than a drift: bash has no floats, so the decider's `$((x * 100 / n))` discarded
# the remainder and could report a ratio marginally under the budget that was over
# it. Rego divides exactly, so the comparison now agrees with the number a reader
# would compute by hand — which is the property the decider's own comment asked for
# ("a gate that rounds is a gate that disagrees with the number it printed").
lane_ratio(key) := value if {
	landings := lane_count_of("landings")
	landings > 0
	value := (lane_count_of(key) * 100) / landings
}

# A window the producer could not read all of. ITS OWN FINDING RATHER THAN A
# DEGRADED PASS, and the truncation in the header is why it is load-bearing.
violation contains {
	"rule": "lane read partial",
	"verdict": "lane read partial",
	"subjects": [{"count": lane_count_of("unreadable")}],
} if {
	lane_count_of("unreadable") > 0
}

# A torn record, under the same class: not part of the window unread, but the
# window's own summary unusable. The count distinguishes never-closed (0) from
# concatenated (2+) from one-but-garbled.
violation contains {
	"rule": "lane read partial",
	"verdict": "lane read partial",
	"subjects": [{"count": count(lane_summaries)}],
} if {
	lane_torn
}

# ANTI-VACUITY IS `ratio`'s GUARD, not an arm of its own: with no landings the
# division is undefined and every ratio rule below is silent, which is the honest
# reading of a quiet day — nothing landed, so nothing diverged. This repo has been
# bitten twice by a gate that cannot fire reading the same as one that found nothing
# (`finding-sink-check`, `bench-assert`), and the record's PRESENCE is what keeps
# the two apart.
violation contains {
	"rule": "lane count spent",
	"verdict": "lane count spent",
	"subjects": [{"count": lane_count_of("graded")}, {"count": lane_count_of("landings")}],
} if {
	lane_ratio("graded") > lane_graded_budget
}

# A red run means `verify` was skipped or disagreed with CI; each one spent a full
# matrix.
violation contains {
	"rule": "lane grade red",
	"verdict": "lane grade red",
	"subjects": [{"count": lane_count_of("red")}, {"count": lane_count_of("landings")}],
} if {
	lane_ratio("red") > lane_red_budget
}

# LATENCY, NEVER COUNT — the header's finding, as a rule.
violation contains {
	"rule": "lane reach late",
	"verdict": "lane reach late",
	"subjects": [{"count": lane_count_of("cancel_p50")}],
} if {
	lane_count_of("cancel_p50") > lane_cancel_budget
}

violation contains {
	"rule": "lease guard dropped",
	"verdict": "lease guard dropped",
	"subjects": [{"count": lane_count_of("peak_concurrency")}],
} if {
	lane_count_of("peak_concurrency") > lane_concurrency_budget
}

# The runner pool saturating, which is a DIFFERENT defect from contention and must
# not be read as one.
violation contains {
	"rule": "lane measure late",
	"verdict": "lane measure late",
	"subjects": [{"count": lane_count_of("queue_p90")}],
} if {
	lane_count_of("queue_p90") > lane_queue_budget
}

# THE SAME WAIT ATTRIBUTED PER JOB (CLOUD-501), and it gets its own rule rather than
# replacing the one above. A run's figure is its FIRST job's start, so a matrix leg
# queueing behind its siblings is invisible in it; the two disagreeing is exactly
# what separates a wide matrix from a saturated pool.
violation contains {
	"rule": "job measure late",
	"verdict": "job measure late",
	"subjects": [{"count": lane_count_of("queue_job_p90")}],
} if {
	lane_count_of("queue_job_p90") > lane_queue_budget
}

# THE ONE METRIC THAT IS NOT A THRESHOLD. A fast-forward refusal means the branch
# went behind before the bot answered — the thundering herd the landing lease
# removed (243:5 before, 0:5 after). Any refusal at all is a divergence, so the
# budget is zero and is written as a literal rather than as a tunable, because
# stating it as one would invite raising it.
violation contains {
	"rule": "branch reach stale",
	"verdict": "branch reach stale",
	"subjects": [{"count": lane_count_of("ff_refused")}],
} if {
	lane_count_of("ff_refused") > 0
}

# --- cases ---------------------------------------------------------------

lane_tree(lines) := {"tree": {"records": {"land-divergence": lines}}}

# A clean window: one landing, one graded green run, nothing waiting.
lane_clean := {
	"landings": 1, "graded": 1, "green": 1, "red": 0, "cancelled": 0,
	"cancel_p50": 0, "peak_concurrency": 1, "queue_p90": 0,
	"queue_job_p90": 0, "retries": 0, "ff_refused": 0, "ff_success": 1,
	"unreadable": 0,
}

lane_window(over) := lane_tree([sprintf(
	"window\tsince=2026-08-12T00:00:00Z\tlandings=%d\tgraded=%d\tgreen=%d\tred=%d\tcancelled=%d\tcancel_p50=%d\tpeak_concurrency=%d\tqueue_p90=%d\tqueue_job_p90=%d\tretries=%d\tff_refused=%d\tff_success=%d\tunreadable=%d",
	[f.landings, f.graded, f.green, f.red, f.cancelled, f.cancel_p50, f.peak_concurrency, f.queue_p90, f.queue_job_p90, f.retries, f.ff_refused, f.ff_success, f.unreadable],
)]) if {
	f := object.union(lane_clean, over)
}

lane_fires(over, id) if {
	some v in violation with input as lane_window(over)
	v.verdict == id
}

test_lane_the_ideal_window_is_clean if {
	count(violation) == 0 with input as lane_window({})
}

# One matrix, run to green, landed — plus the ~20s lease cancellation, which is the
# mechanism WORKING and must sit inside the budget rather than against it.
test_lane_a_lease_cancellation_is_inside_the_budget if {
	count(violation) == 0 with input as lane_window({"graded": 2, "cancelled": 1, "cancel_p50": 20, "peak_concurrency": 2})
}

test_lane_a_loop_buying_three_matrices_per_landing_is_reported if {
	lane_fires({"graded": 3}, "lane count spent")
}

test_lane_a_red_run_over_budget_is_reported if {
	lane_fires({"graded": 2, "red": 1}, "lane grade red")
}

# A LATE CANCEL IS THE FINDING, NOT A CANCEL. This is the case that stops a future
# author "simplifying" the rule into a count.
test_lane_a_late_cancellation_is_reported_where_an_early_one_is_not if {
	lane_fires({"graded": 2, "cancelled": 1, "cancel_p50": 400, "peak_concurrency": 2}, "lane reach late")
	count(violation) == 0 with input as lane_window({"graded": 2, "cancelled": 1, "cancel_p50": 20, "peak_concurrency": 2})
}

test_lane_concurrency_above_the_lease_bound_is_reported if {
	lane_fires({"peak_concurrency": 25}, "lease guard dropped")
}

test_lane_a_saturated_runner_pool_is_reported if {
	lane_fires({"queue_p90": 252}, "lane measure late")
}

# THE TWO QUEUE FIGURES ARE SEPARATE RULES, and this is why: a wide matrix whose
# legs queue behind each other shows a clean run figure and a bad job figure.
test_lane_a_leg_queueing_behind_its_siblings_is_its_own_finding if {
	lane_fires({"queue_job_p90": 252}, "job measure late")
	not lane_fires({"queue_job_p90": 252}, "lane measure late")
}

test_lane_any_fast_forward_refusal_is_reported if {
	lane_fires({"ff_refused": 1}, "branch reach stale")
}

test_lane_a_partially_read_window_is_a_finding if {
	lane_fires({"unreadable": 2}, "lane read partial")
}

# ANTI-VACUITY: a window with no landings judges nothing, because every ratio is
# undefined without a denominator. It is still a reading — the record is present.
test_lane_a_window_with_no_landings_judges_nothing if {
	count(violation) == 0 with input as lane_window({"landings": 0, "graded": 0, "green": 0, "ff_success": 0})
	lane_count_of("landings") == 0 with input as lane_window({"landings": 0, "graded": 0, "green": 0, "ff_success": 0})
}

test_lane_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_lane_a_non_numeric_count_leaves_the_window_unjudged if {
	not lane_count_of("graded") with input as lane_tree(["window\tsince=2026-08-12T00:00:00Z\tlandings=1\tgraded=lots\tgreen=1\tred=0\tcancelled=0\tcancel_p50=0\tpeak_concurrency=1\tqueue_p90=0\tqueue_job_p90=0\tretries=0\tff_refused=0\tff_success=1\tunreadable=0"])
}

# This case used to assert `count(violation) == 0` — it pinned the silence the
# port had dropped the refusal for. Neither window is judged against a budget;
# the record is refused as torn, and only as torn.
test_lane_two_concatenated_measurements_judge_neither_window if {
	lines := array.concat(
		lane_window({"graded": 9}).tree.records["land-divergence"],
		lane_window({"graded": 3, "landings": 2}).tree.records["land-divergence"],
	)
	found := violation with input as lane_tree(lines)
	found == {{"rule": "lane read partial", "verdict": "lane read partial", "subjects": [{"count": 2}]}}
}

# THE MUTATION'S NAMED CASE: each torn shape is a finding, and the clean window
# is not. Three shapes, one per arm of `torn`.
test_lane_a_torn_record_is_a_finding_rather_than_a_clean_window if {
	count(violation) == 1 with input as lane_tree(["nonsense"])
	count(violation) == 1 with input as lane_tree(["window\tsince=2026-08-12T00:00:00Z\tlandings=1\tgraded=lots\tgreen=1\tred=0\tcancelled=0\tcancel_p50=0\tpeak_concurrency=1\tqueue_p90=0\tqueue_job_p90=0\tretries=0\tff_refused=0\tff_success=1\tunreadable=0"])
	count(violation) == 1 with input as lane_tree(["window\tsince=2026-08-12T00:00:00Z\tlandings=1"])
	count(violation) == 0 with input as lane_window({})
}

# A line this reader cannot parse is skipped; the summary survives, so this passes
# for the reason it says rather than because the window went missing.
test_lane_a_line_this_reader_cannot_parse_is_skipped if {
	lines := array.concat(lane_window({}).tree.records["land-divergence"], ["nonsense"])
	count(violation) == 0 with input as lane_tree(lines)
}
