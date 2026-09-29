# CI signal: a required job's failure reaches a verdict (CLOUD-484, ported under
# CLOUD-1717, and out of a consumer module into this preset under CLOUD-843).
#
# A job that dies in provisioning — checkout, the toolchain install, a cache
# restore — spends its runner minutes, reds the branch, and answers nothing. Every
# occurrence then costs a human or an agent the time to discover it was never a
# verdict at all. This answers HOW OFTEN, so a step change is visible as a number
# instead of as whoever gets bitten next.
#
# THE CLASSIFICATION IS THE PRODUCER'S AND IT IS CLOSED. `batten record
# nonverdict` reads each failed required job's own `steps[]` and calls it a verdict
# iff one of its failed steps starts with a prefix the consumer names as
# verdict-bearing; the roster, the fan-in and the prefixes are the consumer's, fed
# to the verb, so none of them is here. What reaches this module is a window of
# `verdict` / `nonverdict` lines and one summary — a shape any consumer's producer
# run writes, under the verb's own fixed `nonverdict` family (rule 1).
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, EXCEPT WHERE IT IS PARTIAL. Total blindness
# — no roster, an unreadable run list — is the producer refusing at write time and
# removing any stale record, which reads here as silence. `unreadable` is the
# third case and is NOT blindness: the producer read part of its window, which is
# the partial-coverage false green and a finding in its own right.
#
# EVERY NAME IS PREFIXED `job_`: a preset's modules share one `package`, and its
# sibling binds the same shapes under `lane_`. Re-binding one does not shadow.
#MUTANT-SUITE crates/batten/tests/it/nonverdict.rs
#MUTANT job-over-budget-passes|s@^\tjob_count_of("nonverdict") > job_budget$@\tfalse@|an_over_budget_window_is_reported_over_the_engines_projection
#MUTANT job-partial-window-passes|s@^\tjob_count_of("unreadable") > 0$@\tfalse@|nonverdict::a_partially_read_window_is_a_finding_rather_than_a_clean_one
#MUTANT job-torn-record-passes|s@^\tcount(job_summaries) != 1$@\tfalse@|nonverdict::a_torn_record_is_a_finding_rather_than_a_clean_window
#MUTANT job-verdict-failures-counted|s@^\tcolumns\[0\] == "nonverdict"$@\tcolumns[0] != "window"@|a_verdict_failure_is_never_named_however_many_there_are

# METADATA
# description: |
#   Bound to the TREE surface: the enabling row is `scope = "tree"`, so this
#   reads `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]

package batten.ci_signal

import rego.v1

rules contains "job read partial"

rules contains "job answer missing"

# How many non-verdict job failures a window may carry before this fires.
#
# TWO, NOT ZERO, and the retired program's reasoning is the one that carries: one
# provisioning failure in a window is the platform having a bad afternoon and is
# not actionable; a third in the same window is a pattern, and hearing about the
# pattern before the minutes are spent is the whole point.
#
# IN THE MODULE RATHER THAN BEHIND AN ENV OVERRIDE, which is `timeout-drift.rego`'s
# placement for its multipliers and is what the port made possible. The shell's
# `BATTEN_NONVERDICT_MAX` existed so its suite could point the budget at a fixture;
# a module's cases vary the COUNTS instead, so the knob had one reader and that
# reader no longer needs it.
job_budget := 2

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
job_recorded := input.tree.records.nonverdict

# The one summary line, held as a set so that a store carrying the same summary
# twice is still one window.
#
# EXACTLY ONE, OR THE RECORD IS TORN — AND TORN IS A FINDING. Two DIFFERENT
# summaries mean two scans were concatenated and a count over both describes
# neither; no summary means the window was never closed. The retired decider
# refused both (`nonverdict-assert.sh:85-86,92-93`). The first port gated
# `fields` on `count(summaries) == 1` and stopped there, so every rule below went
# undefined and a torn store read GREEN — while this comment claimed the arm was
# kept. `torn` below is that arm, actually kept.
job_summaries contains raw if {
	some raw in job_recorded
	startswith(raw, "window\t")
}

# `window\truns=<n>\tfailed_jobs=<k>\tnonverdict=<m>\tverdict=<v>\tunreadable=<u>`
# flattened to an object. A malformed column is skipped rather than fatal, the
# posture every record reader here takes: the producer refuses a malformed line at
# write time, so one arriving at read time is a torn store.
job_fields[pair[0]] := pair[1] if {
	count(job_summaries) == 1
	some raw in job_summaries
	columns := split(raw, "\t")
	some idx in numbers.range(1, count(columns) - 1)
	pair := split(columns[idx], "=")
	count(pair) == 2
}

# A COUNT THAT IS NOT A NUMBER IS NOT A ZERO. The retired decider refused rather
# than coercing, because a count silently read as zero is a clean window over input
# nobody parsed (`nonverdict-assert.sh:115-116`). Undefined here would leave both
# rules below unfired and the window unjudged, so `torn` reads a missing or
# non-numeric column as a refusal rather than letting it go silent.
job_count_of(key) := number if {
	raw := job_fields[key]
	regex.match("^[0-9]+$", raw)
	number := to_number(raw)
}

# The columns every closed window carries.
job_window_columns := {"runs", "failed_jobs", "nonverdict", "verdict", "unreadable"}

# A record is present but its summary cannot be trusted: none, more than one, or
# one missing or garbling a column. `recorded` is DEFINED in every one of these,
# which is exactly why they are distinguishable from could-not-look (no record at
# all) and must not collapse into it.
job_torn if {
	job_recorded
	count(job_summaries) != 1
}

job_torn if {
	count(job_summaries) == 1
	some key in job_window_columns
	not job_count_of(key)
}

# `nonverdict\trun=<id>\tjob=<name>\tstep=<name>` — one per required job that
# failed before any `mise` step. The `verdict` lines are deliberately not read
# here: they exist so the ratio is derivable and so a window that found only
# verdicts is distinguishable from one that found nothing.
job_failures contains {
	"run": trim_prefix(columns[1], "run="),
	"job": trim_prefix(columns[2], "job="),
	"step": trim_prefix(columns[3], "step="),
} if {
	some raw in job_recorded
	columns := split(raw, "\t")
	count(columns) == 4
	columns[0] == "nonverdict"
	startswith(columns[1], "run=")
	startswith(columns[2], "job=")
	startswith(columns[3], "step=")
}

# A window the producer could not read all of.
#
# ITS OWN FINDING RATHER THAN A DEGRADED PASS. This is `bench-assert`'s
# partial-coverage rule: "a run that measured two of three paths and reported green
# over the two is exactly the partial-coverage false green". It fires whatever the
# count is, because a budget met over part of a window is a budget met over nothing
# in particular.
violation contains {
	"rule": "job read partial",
	"verdict": "job read partial",
	"subjects": [{"count": job_count_of("unreadable")}],
} if {
	job_count_of("unreadable") > 0
}

# A torn record — the same class, because it is the same false green one step
# worse: not part of the window unread, but the window's own summary unusable.
# The count is how many summaries the store held, which is what a reader needs to
# tell "never closed" (0) from "two scans concatenated" (2+) from "one, garbled".
violation contains {
	"rule": "job read partial",
	"verdict": "job read partial",
	"subjects": [{"count": count(job_summaries)}],
} if {
	job_torn
}

# Each job that spent its minutes and answered nothing, once the window is over
# budget.
#
# ONE FINDING PER JOB, not one per window: the count is what decides, and the
# coordinates are what a reader acts on. ANTI-VACUITY needs no arm of its own —
# a window with no runs carries no `nonverdict` line, so it cannot fire — and the
# case below is what keeps that true rather than accidental. This repo has been
# bitten twice by a gate that cannot fire reading the same as one that found
# nothing (`finding-sink-check`, `bench-assert`).
violation contains {
	"rule": "job answer missing",
	"verdict": "job answer missing",
	"subjects": [{"artifact": entry.job}, {"artifact": entry.run}, {"artifact": entry.step}],
} if {
	job_count_of("nonverdict") > job_budget
	some entry in job_failures
}

# --- cases ---------------------------------------------------------------

job_tree(lines) := {"tree": {"records": {"nonverdict": lines}}}

job_summary(runs, nonverdict, unreadable) := sprintf(
	"window\truns=%d\tfailed_jobs=%d\tnonverdict=%d\tverdict=0\tunreadable=%d",
	[runs, nonverdict, nonverdict, unreadable],
)

job_failure(run, job, step) := sprintf("nonverdict\trun=%s\tjob=%s\tstep=%s", [run, job, step])

job_window(runs, unreadable, failed) := job_tree(array.concat(
	[job_summary(runs, count(failed), unreadable)],
	failed,
))

test_job_under_budget_is_clean if {
	count(violation) == 0 with input as job_window(10, 0, [
		job_failure("111", "ci", "Run actions/checkout@3d3c42e"),
		job_failure("222", "msrv", "Run actions/checkout@3d3c42e"),
	])
}

test_job_over_budget_names_each_non_verdict_failure if {
	found := violation with input as job_window(10, 0, [
		job_failure("111", "ci", "Run actions/checkout@3d3c42e"),
		job_failure("222", "msrv", "Run actions/checkout@3d3c42e"),
		job_failure("333", "cross", "Set up job"),
	])
	count(found) == 3
	every v in found {
		v.verdict == "job answer missing"
	}
}

# POINTER, NEVER PAYLOAD (rule 4): run ids, job names and step names. The producer
# never fetches a log body, so there is none here to leak.
test_job_the_finding_carries_coordinates_and_nothing_else if {
	some v in violation with input as job_window(10, 0, [
		job_failure("111", "ci", "Run actions/checkout@3d3c42e"),
		job_failure("222", "msrv", "Run actions/checkout@3d3c42e"),
		job_failure("333", "cross", "Set up job"),
	])
	v.subjects[0] == {"artifact": "ci"}
}

# A VERDICT FAILURE IS NOT COUNTED, however many there are: it was judged, and the
# branch that caused it is the thing to fix.
test_job_a_verdict_failure_is_never_named if {
	count(violation) == 0 with input as job_tree([
		"window\truns=10\tfailed_jobs=9\tnonverdict=0\tverdict=9\tunreadable=0",
		"verdict\trun=111\tjob=ci\tstep=Run mise run test:cargo",
		"verdict\trun=222\tjob=msrv\tstep=Run mise exec -- cargo check",
	])
}

# COULD NOT LOOK AT PART OF IT is a finding, and fires even under budget: a green
# verdict here would cover less than it claims.
test_job_an_unreadable_run_is_a_finding_even_under_budget if {
	some v in violation with input as job_window(10, 3, [])
	v.verdict == "job read partial"
}

test_job_the_partial_finding_carries_the_count if {
	some v in violation with input as job_window(10, 3, [])
	v.subjects == [{"count": 3}]
}

# ANTI-VACUITY: a window with nothing in it judges nothing and says so by being
# present. An absent record is nobody having looked; this is the producer having
# looked and found no failed required job.
test_job_an_empty_window_fires_nothing_but_is_still_a_reading if {
	count(violation) == 0 with input as job_window(0, 0, [])
	job_count_of("runs") == 0 with input as job_window(0, 0, [])
}

test_job_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A COUNT THAT IS NOT A NUMBER IS NOT A ZERO. Coercing would report a clean window
# over input nobody parsed.
test_job_a_non_numeric_count_leaves_the_window_unjudged if {
	not job_count_of("nonverdict") with input as job_tree(["window\truns=10\tfailed_jobs=1\tnonverdict=lots\tverdict=0\tunreadable=0"])
}

# Two DIFFERENT summaries describe neither window. This case used to assert
# `count(violation) == 0` — it pinned the silence the port had dropped the
# refusal for. The window is still not judged against the budget; it is refused
# as torn, and ONLY as torn.
test_job_two_concatenated_scans_judge_neither_window if {
	found := violation with input as job_tree([
		"window\truns=10\tfailed_jobs=4\tnonverdict=4\tverdict=0\tunreadable=0",
		"window\truns=10\tfailed_jobs=9\tnonverdict=9\tverdict=0\tunreadable=0",
		job_failure("111", "ci", "Run actions/checkout@3d3c42e"),
	])
	found == {{"rule": "job read partial", "verdict": "job read partial", "subjects": [{"count": 2}]}}
}

# THE MUTATION'S NAMED CASE: every torn shape is a finding, and a clean window is
# not. Three torn shapes, because each reaches `torn` by a different arm.
test_job_a_torn_record_is_a_finding_rather_than_a_clean_window if {
	no_summary := violation with input as job_tree([job_failure("111", "ci", "Set up job")])
	count(no_summary) == 1
	garbled := violation with input as job_tree(["window\truns=10\tfailed_jobs=1\tnonverdict=lots\tverdict=0\tunreadable=0"])
	count(garbled) == 1
	missing := violation with input as job_tree(["window\truns=10\tfailed_jobs=1\tverdict=0\tunreadable=0"])
	count(missing) == 1
	count(violation) == 0 with input as job_window(10, 0, [])
}

# ABSENT IS NOT TORN. No record at all is could-not-look, which the producer
# refuses at write time; this module must not read it as a finding, or every
# checkout that never ran the producer refuses.
test_job_an_absent_record_is_not_torn if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A line this reader cannot parse is skipped. The surviving good lines are part of
# the case: without them the record holds no window at all, and this would pass for
# a reason that has nothing to do with skipping.
test_job_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as job_tree([
		"window\truns=10\tfailed_jobs=1\tnonverdict=1\tverdict=0\tunreadable=0",
		job_failure("111", "ci", "Run actions/checkout@3d3c42e"),
		"nonsense",
	])
}
