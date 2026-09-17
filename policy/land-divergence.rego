# How far the landing loop diverged from linear over a window (CLOUD-492, ported
# under CLOUD-1717).
#
# THE CLAIM BEING GRADED. The loop is serialised behind a lease (CLOUD-393) and an
# unauthorised matrix is stopped server-side (CLOUD-420). Together those claim a PR
# buys ONE CI matrix, runs it to green, and lands. Divergence from that is the whole
# signal, and it was established once by hand — ~50 paginated calls and throwaway
# jq — which is why nothing could see a step change BETWEEN two assessments.
#
# THE SPLIT WAS ALREADY THERE AND THE PORT ONLY MOVED ITS HALVES, exactly as the
# `nonverdict` pair's was: `land-divergence` measured and `land-divergence-assert`
# decided, kept apart because a measurement needs the network and a token and a
# decision needs neither (CLOUD-1559). The measurement is
# `[tasks.land-divergence-record]`; this file is the decision, and no decision
# changed hands. The pagination walk, the ETag cache, the `total_count` truncation
# guard and every instant subtraction stay outside: house style §5 makes `check`
# `read` and incapable of spawning, and `Fact::Instant` projects `null` to every
# module, which `clippy.toml` and `crates/batten/tests/clock_ban.rs` hold.
#
# A CANCELLED RUN IS NOT WASTE, AND COUNTING THEM INVERTS THE VERDICT. This is the
# finding the pair exists to encode. Measured 2026-08-12 after serialisation: 5
# green CI runs against 5 cancelled, which reads as a 50% discard rate and is the
# opposite — those cancels had p50 lifetime ~20s, `ci-lease-precondition` killing an
# unauthorised matrix for ~20 runner-seconds instead of billing ~500. Before
# serialisation the same population had p75 147s. So the graded quantity is CANCEL
# LATENCY, never cancel count: a rule counting cancels would score the working
# precondition as a defect and argue for removing it.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, EXCEPT WHERE IT IS PARTIAL. The retired
# decider ran `0/1/2` with `2` for could-not-look, and the engine's `2` is a
# FINDING. Both total-blindness arms — an unreadable CI run window, an unreadable
# merged-PR list — are now the producer refusing at write time and recording
# nothing, which reads here as silence. `unreadable` is the third case and is not
# blindness: the producer read PART of its window and judged less than it claims,
# which is `bench-assert`'s partial-coverage false green and its own finding.
#
# THE TRUNCATION THAT MAKES THAT ARM LOAD-BEARING, measured rather than reasoned:
# the Actions runs endpoint hard-caps pagination at 1000 items while still reporting
# the true `total_count`. Over a 25-hour window on `fast-forward.yml` it reported
# 1446 with page 10 full and page 11 empty, so a walk that stops on a short page
# collects 1000 of 1446 and looks like a clean finish — it reported `ff_refused=0`
# over a window carrying 598 refusals. A perfect score read off a prefix.
#MUTANT-SUITE crates/batten/tests/it/land_divergence.rs
#MUTANT partial-window-passes|s@^\tcount_of("unreadable") > 0$@\tfalse@|a_partially_read_window_is_a_finding_rather_than_a_clean_one
#MUTANT graded-over-budget-passes|s@^\tratio("graded") > graded_budget$@\tfalse@|a_loop_buying_more_than_one_matrix_per_landing_is_reported
#MUTANT refusal-budget-loosened|s@^\tcount_of("ff_refused") > 0$@\tfalse@|any_fast_forward_refusal_at_all_is_reported

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.land_divergence

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
graded_budget := 200

red_budget := 20

# Seconds. An early cancellation is the lease precondition working; a late one is a
# matrix billed for a verdict nobody reads.
cancel_budget := 60

# Landing is serialised behind a lease, so concurrency above the admitted-successor
# bound means something is spending CI without holding it.
concurrency_budget := 3

# Seconds, and the same figure for both: the ideal is that a run — and each of its
# legs — starts when it is created.
queue_budget := 30

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
recorded := input.tree.records["land-divergence"]

# EXACTLY ONE SUMMARY, OR NOTHING IS JUDGED. Two DIFFERENT summaries mean two
# measurements were concatenated and a count over both describes neither — the
# retired decider's own arm, kept, and reachable here only through a torn store
# because `record named` replaces a family rather than appending to it.
summaries contains raw if {
	some raw in recorded
	startswith(raw, "window\t")
}

fields[pair[0]] := pair[1] if {
	count(summaries) == 1
	some raw in summaries
	columns := split(raw, "\t")
	some idx in numbers.range(1, count(columns) - 1)
	pair := split(columns[idx], "=")
	count(pair) == 2
}

# A COUNT THAT IS NOT A NUMBER IS NOT A ZERO. The retired decider refused rather
# than coercing, because a count silently read as zero is a clean window over input
# nobody parsed. Here that refusal is undefinedness, which leaves the rule unfired.
count_of(key) := number if {
	raw := fields[key]
	regex.match(data.batten.patterns["whole-number"], raw)
	number := to_number(raw)
}

# Per-landing, in hundredths.
#
# TRUE DIVISION WHERE THE SHELL TRUNCATED, which is a fidelity improvement rather
# than a drift: bash has no floats, so the decider's `$((x * 100 / n))` discarded
# the remainder and could report a ratio marginally under the budget that was over
# it. Rego divides exactly, so the comparison now agrees with the number a reader
# would compute by hand — which is the property the decider's own comment asked for
# ("a gate that rounds is a gate that disagrees with the number it printed").
ratio(key) := value if {
	landings := count_of("landings")
	landings > 0
	value := (count_of(key) * 100) / landings
}

# A window the producer could not read all of. ITS OWN FINDING RATHER THAN A
# DEGRADED PASS, and the truncation in the header is why it is load-bearing.
violation contains {
	"rule": "lane read partial",
	"verdict": "lane read partial",
	"subjects": [{"count": count_of("unreadable")}],
} if {
	count_of("unreadable") > 0
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
	"subjects": [{"count": count_of("graded")}, {"count": count_of("landings")}],
} if {
	ratio("graded") > graded_budget
}

# A red run means `verify` was skipped or disagreed with CI; each one spent a full
# matrix.
violation contains {
	"rule": "lane grade red",
	"verdict": "lane grade red",
	"subjects": [{"count": count_of("red")}, {"count": count_of("landings")}],
} if {
	ratio("red") > red_budget
}

# LATENCY, NEVER COUNT — the header's finding, as a rule.
violation contains {
	"rule": "lane reach late",
	"verdict": "lane reach late",
	"subjects": [{"count": count_of("cancel_p50")}],
} if {
	count_of("cancel_p50") > cancel_budget
}

violation contains {
	"rule": "lease guard dropped",
	"verdict": "lease guard dropped",
	"subjects": [{"count": count_of("peak_concurrency")}],
} if {
	count_of("peak_concurrency") > concurrency_budget
}

# The runner pool saturating, which is a DIFFERENT defect from contention and must
# not be read as one.
violation contains {
	"rule": "lane measure late",
	"verdict": "lane measure late",
	"subjects": [{"count": count_of("queue_p90")}],
} if {
	count_of("queue_p90") > queue_budget
}

# THE SAME WAIT ATTRIBUTED PER JOB (CLOUD-501), and it gets its own rule rather than
# replacing the one above. A run's figure is its FIRST job's start, so a matrix leg
# queueing behind its siblings is invisible in it; the two disagreeing is exactly
# what separates a wide matrix from a saturated pool.
violation contains {
	"rule": "job measure late",
	"verdict": "job measure late",
	"subjects": [{"count": count_of("queue_job_p90")}],
} if {
	count_of("queue_job_p90") > queue_budget
}

# THE ONE METRIC THAT IS NOT A THRESHOLD. A fast-forward refusal means the branch
# went behind before the bot answered — the thundering herd the landing lease
# removed (243:5 before, 0:5 after). Any refusal at all is a divergence, so the
# budget is zero and is written as a literal rather than as a tunable, because
# stating it as one would invite raising it.
violation contains {
	"rule": "branch reach stale",
	"verdict": "branch reach stale",
	"subjects": [{"count": count_of("ff_refused")}],
} if {
	count_of("ff_refused") > 0
}

# --- cases ---------------------------------------------------------------

tree(lines) := {"tree": {"records": {"land-divergence": lines}}}

# A clean window: one landing, one graded green run, nothing waiting.
clean := {
	"landings": 1, "graded": 1, "green": 1, "red": 0, "cancelled": 0,
	"cancel_p50": 0, "peak_concurrency": 1, "queue_p90": 0,
	"queue_job_p90": 0, "retries": 0, "ff_refused": 0, "ff_success": 1,
	"unreadable": 0,
}

window(over) := tree([sprintf(
	"window\tsince=2026-08-12T00:00:00Z\tlandings=%d\tgraded=%d\tgreen=%d\tred=%d\tcancelled=%d\tcancel_p50=%d\tpeak_concurrency=%d\tqueue_p90=%d\tqueue_job_p90=%d\tretries=%d\tff_refused=%d\tff_success=%d\tunreadable=%d",
	[f.landings, f.graded, f.green, f.red, f.cancelled, f.cancel_p50, f.peak_concurrency, f.queue_p90, f.queue_job_p90, f.retries, f.ff_refused, f.ff_success, f.unreadable],
)]) if {
	f := object.union(clean, over)
}

fires(over, id) if {
	some v in violation with input as window(over)
	v.verdict == id
}

test_the_ideal_window_is_clean if {
	count(violation) == 0 with input as window({})
}

# One matrix, run to green, landed — plus the ~20s lease cancellation, which is the
# mechanism WORKING and must sit inside the budget rather than against it.
test_a_lease_cancellation_is_inside_the_budget if {
	count(violation) == 0 with input as window({"graded": 2, "cancelled": 1, "cancel_p50": 20, "peak_concurrency": 2})
}

test_a_loop_buying_three_matrices_per_landing_is_reported if {
	fires({"graded": 3}, "lane count spent")
}

test_a_red_run_over_budget_is_reported if {
	fires({"graded": 2, "red": 1}, "lane grade red")
}

# A LATE CANCEL IS THE FINDING, NOT A CANCEL. This is the case that stops a future
# author "simplifying" the rule into a count.
test_a_late_cancellation_is_reported_where_an_early_one_is_not if {
	fires({"graded": 2, "cancelled": 1, "cancel_p50": 400, "peak_concurrency": 2}, "lane reach late")
	count(violation) == 0 with input as window({"graded": 2, "cancelled": 1, "cancel_p50": 20, "peak_concurrency": 2})
}

test_concurrency_above_the_lease_bound_is_reported if {
	fires({"peak_concurrency": 25}, "lease guard dropped")
}

test_a_saturated_runner_pool_is_reported if {
	fires({"queue_p90": 252}, "lane measure late")
}

# THE TWO QUEUE FIGURES ARE SEPARATE RULES, and this is why: a wide matrix whose
# legs queue behind each other shows a clean run figure and a bad job figure.
test_a_leg_queueing_behind_its_siblings_is_its_own_finding if {
	fires({"queue_job_p90": 252}, "job measure late")
	not fires({"queue_job_p90": 252}, "lane measure late")
}

test_any_fast_forward_refusal_is_reported if {
	fires({"ff_refused": 1}, "branch reach stale")
}

test_a_partially_read_window_is_a_finding if {
	fires({"unreadable": 2}, "lane read partial")
}

# ANTI-VACUITY: a window with no landings judges nothing, because every ratio is
# undefined without a denominator. It is still a reading — the record is present.
test_a_window_with_no_landings_judges_nothing if {
	count(violation) == 0 with input as window({"landings": 0, "graded": 0, "green": 0, "ff_success": 0})
	count_of("landings") == 0 with input as window({"landings": 0, "graded": 0, "green": 0, "ff_success": 0})
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_non_numeric_count_leaves_the_window_unjudged if {
	not count_of("graded") with input as tree(["window\tsince=2026-08-12T00:00:00Z\tlandings=1\tgraded=lots\tgreen=1\tred=0\tcancelled=0\tcancel_p50=0\tpeak_concurrency=1\tqueue_p90=0\tqueue_job_p90=0\tretries=0\tff_refused=0\tff_success=1\tunreadable=0"])
}

test_two_concatenated_measurements_judge_neither_window if {
	lines := array.concat(
		window({"graded": 9}).tree.records["land-divergence"],
		window({"graded": 3, "landings": 2}).tree.records["land-divergence"],
	)
	count(violation) == 0 with input as tree(lines)
}

# A line this reader cannot parse is skipped; the summary survives, so this passes
# for the reason it says rather than because the window went missing.
test_a_line_this_reader_cannot_parse_is_skipped if {
	lines := array.concat(window({}).tree.records["land-divergence"], ["nonsense"])
	count(violation) == 0 with input as tree(lines)
}
