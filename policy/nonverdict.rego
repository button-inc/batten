# How often a required CI job fails WITHOUT ever reaching a verdict (CLOUD-484,
# ported under CLOUD-1717).
#
# A job that dies in provisioning — checkout, the toolchain install, a cache
# restore — spends its runner minutes, reds the branch, and answers nothing. Every
# occurrence then costs a human or an agent the time to discover it was never a
# verdict at all: CLOUD-404 has five, and the one on #376 sent an agent to
# reproduce a `commit-lint` failure that passes locally because `commit-lint`
# never linted anything. CLOUD-483 stops `land` MISREADING one in the moment; this
# answers the question neither of those does — HOW OFTEN — so a step change is
# visible as a number instead of as whoever gets bitten next.
#
# THE SPLIT WAS ALREADY THERE AND THE PORT ONLY MOVED ITS HALVES. The retired pair
# was `nonverdict-scan` (measure) and `nonverdict-assert` (decide), kept apart for
# exactly CLOUD-1559's reason: a measurement needs the network and a token, a
# decision needs neither. So the scan became `[tasks.nonverdict-record]` and the
# assert became this file, and no decision changed hands — which is why the
# classification predicate below is absent from here. Whether a failed step is a
# verdict is read off the API payload's own `steps[]`, which `check` cannot fetch
# (house style §5 makes it `read` and incapable of spawning).
#
# THE PREDICATE IS THE PRODUCER'S AND IT IS CLOSED. A failed job rendered a VERDICT
# iff one of its failed steps is named `Run mise run <task>` or
# `Run mise exec -- <command>`; otherwise it failed without reaching one. The
# second spelling was added after the first cost four jobs in one lap (CLOUD-113):
# the `windows` job runs `mise exec -- cargo test` because `mise run` puts Git Bash
# between the runner and cargo, so seven genuinely failing tests classified as a
# provisioning transient and `land` re-ran the job four times. A predicate whose
# premise has gone false does not fail loudly; it answers confidently and wrongly,
# in the direction that spends money.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, EXCEPT WHERE IT IS PARTIAL. The retired
# decider ran `0/1/2` with `2` for could-not-look, and the engine's `2` is a
# FINDING — so the two total-blindness arms (an empty roster, an unreadable run
# list) are now the producer refusing at write time and recording nothing, which
# reads here as silence. `unreadable` is the third case and is NOT blindness: the
# producer read part of its window and judged less than it claims, which is
# `bench-assert`'s partial-coverage false green and a finding in its own right.
#MUTANT-SUITE crates/batten/tests/it/nonverdict.rs
#MUTANT over-budget-passes|s@^\tcount_of("nonverdict") > budget$@\tfalse@|an_over_budget_window_is_reported_over_the_engines_projection
#MUTANT partial-window-passes|s@^\tcount_of("unreadable") > 0$@\tfalse@|a_partially_read_window_is_a_finding_rather_than_a_clean_one
#MUTANT torn-record-passes|s@^\tcount(summaries) != 1$@\tfalse@|a_torn_record_is_a_finding_rather_than_a_clean_window
#MUTANT verdict-failures-counted|s@^\tcolumns\[0\] == "nonverdict"$@\tcolumns[0] != "window"@|a_verdict_failure_is_never_named_however_many_there_are

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.nonverdict

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
budget := 2

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
recorded := input.tree.records.nonverdict

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
summaries contains raw if {
	some raw in recorded
	startswith(raw, "window\t")
}

# `window\truns=<n>\tfailed_jobs=<k>\tnonverdict=<m>\tverdict=<v>\tunreadable=<u>`
# flattened to an object. A malformed column is skipped rather than fatal, the
# posture every record reader here takes: the producer refuses a malformed line at
# write time, so one arriving at read time is a torn store.
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
# nobody parsed (`nonverdict-assert.sh:115-116`). Undefined here would leave both
# rules below unfired and the window unjudged, so `torn` reads a missing or
# non-numeric column as a refusal rather than letting it go silent.
count_of(key) := number if {
	raw := fields[key]
	regex.match(data.batten.patterns["whole-number"], raw)
	number := to_number(raw)
}

# The columns every closed window carries.
window_columns := {"runs", "failed_jobs", "nonverdict", "verdict", "unreadable"}

# A record is present but its summary cannot be trusted: none, more than one, or
# one missing or garbling a column. `recorded` is DEFINED in every one of these,
# which is exactly why they are distinguishable from could-not-look (no record at
# all) and must not collapse into it.
torn if {
	recorded
	count(summaries) != 1
}

torn if {
	count(summaries) == 1
	some key in window_columns
	not count_of(key)
}

# `nonverdict\trun=<id>\tjob=<name>\tstep=<name>` — one per required job that
# failed before any `mise` step. The `verdict` lines are deliberately not read
# here: they exist so the ratio is derivable and so a window that found only
# verdicts is distinguishable from one that found nothing.
failures contains {
	"run": trim_prefix(columns[1], "run="),
	"job": trim_prefix(columns[2], "job="),
	"step": trim_prefix(columns[3], "step="),
} if {
	some raw in recorded
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
	"subjects": [{"count": count_of("unreadable")}],
} if {
	count_of("unreadable") > 0
}

# A torn record — the same class, because it is the same false green one step
# worse: not part of the window unread, but the window's own summary unusable.
# The count is how many summaries the store held, which is what a reader needs to
# tell "never closed" (0) from "two scans concatenated" (2+) from "one, garbled".
violation contains {
	"rule": "job read partial",
	"verdict": "job read partial",
	"subjects": [{"count": count(summaries)}],
} if {
	torn
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
	count_of("nonverdict") > budget
	some entry in failures
}

# --- cases ---------------------------------------------------------------

tree(lines) := {"tree": {"records": {"nonverdict": lines}}}

summary(runs, nonverdict, unreadable) := sprintf(
	"window\truns=%d\tfailed_jobs=%d\tnonverdict=%d\tverdict=0\tunreadable=%d",
	[runs, nonverdict, nonverdict, unreadable],
)

failure(run, job, step) := sprintf("nonverdict\trun=%s\tjob=%s\tstep=%s", [run, job, step])

window(runs, unreadable, failed) := tree(array.concat(
	[summary(runs, count(failed), unreadable)],
	failed,
))

test_under_budget_is_clean if {
	count(violation) == 0 with input as window(10, 0, [
		failure("111", "ci", "Run actions/checkout@3d3c42e"),
		failure("222", "msrv", "Run actions/checkout@3d3c42e"),
	])
}

test_over_budget_names_each_non_verdict_failure if {
	found := violation with input as window(10, 0, [
		failure("111", "ci", "Run actions/checkout@3d3c42e"),
		failure("222", "msrv", "Run actions/checkout@3d3c42e"),
		failure("333", "cross", "Set up job"),
	])
	count(found) == 3
	every v in found {
		v.verdict == "job answer missing"
	}
}

# POINTER, NEVER PAYLOAD (rule 4): run ids, job names and step names. The producer
# never fetches a log body, so there is none here to leak.
test_the_finding_carries_coordinates_and_nothing_else if {
	some v in violation with input as window(10, 0, [
		failure("111", "ci", "Run actions/checkout@3d3c42e"),
		failure("222", "msrv", "Run actions/checkout@3d3c42e"),
		failure("333", "cross", "Set up job"),
	])
	v.subjects[0] == {"artifact": "ci"}
}

# A VERDICT FAILURE IS NOT COUNTED, however many there are: it was judged, and the
# branch that caused it is the thing to fix.
test_a_verdict_failure_is_never_named if {
	count(violation) == 0 with input as tree([
		"window\truns=10\tfailed_jobs=9\tnonverdict=0\tverdict=9\tunreadable=0",
		"verdict\trun=111\tjob=ci\tstep=Run mise run test:cargo",
		"verdict\trun=222\tjob=msrv\tstep=Run mise exec -- cargo check",
	])
}

# COULD NOT LOOK AT PART OF IT is a finding, and fires even under budget: a green
# verdict here would cover less than it claims.
test_an_unreadable_run_is_a_finding_even_under_budget if {
	some v in violation with input as window(10, 3, [])
	v.verdict == "job read partial"
}

test_the_partial_finding_carries_the_count if {
	some v in violation with input as window(10, 3, [])
	v.subjects == [{"count": 3}]
}

# ANTI-VACUITY: a window with nothing in it judges nothing and says so by being
# present. An absent record is nobody having looked; this is the producer having
# looked and found no failed required job.
test_an_empty_window_fires_nothing_but_is_still_a_reading if {
	count(violation) == 0 with input as window(0, 0, [])
	count_of("runs") == 0 with input as window(0, 0, [])
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A COUNT THAT IS NOT A NUMBER IS NOT A ZERO. Coercing would report a clean window
# over input nobody parsed.
test_a_non_numeric_count_leaves_the_window_unjudged if {
	not count_of("nonverdict") with input as tree(["window\truns=10\tfailed_jobs=1\tnonverdict=lots\tverdict=0\tunreadable=0"])
}

# Two DIFFERENT summaries describe neither window. This case used to assert
# `count(violation) == 0` — it pinned the silence the port had dropped the
# refusal for. The window is still not judged against the budget; it is refused
# as torn, and ONLY as torn.
test_two_concatenated_scans_judge_neither_window if {
	found := violation with input as tree([
		"window\truns=10\tfailed_jobs=4\tnonverdict=4\tverdict=0\tunreadable=0",
		"window\truns=10\tfailed_jobs=9\tnonverdict=9\tverdict=0\tunreadable=0",
		failure("111", "ci", "Run actions/checkout@3d3c42e"),
	])
	found == {{"rule": "job read partial", "verdict": "job read partial", "subjects": [{"count": 2}]}}
}

# THE MUTATION'S NAMED CASE: every torn shape is a finding, and a clean window is
# not. Three torn shapes, because each reaches `torn` by a different arm.
test_a_torn_record_is_a_finding_rather_than_a_clean_window if {
	no_summary := violation with input as tree([failure("111", "ci", "Set up job")])
	count(no_summary) == 1
	garbled := violation with input as tree(["window\truns=10\tfailed_jobs=1\tnonverdict=lots\tverdict=0\tunreadable=0"])
	count(garbled) == 1
	missing := violation with input as tree(["window\truns=10\tfailed_jobs=1\tverdict=0\tunreadable=0"])
	count(missing) == 1
	count(violation) == 0 with input as window(10, 0, [])
}

# ABSENT IS NOT TORN. No record at all is could-not-look, which the producer
# refuses at write time; this module must not read it as a finding, or every
# checkout that never ran the producer refuses.
test_an_absent_record_is_not_torn if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A line this reader cannot parse is skipped. The surviving good lines are part of
# the case: without them the record holds no window at all, and this would pass for
# a reason that has nothing to do with skipping.
test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as tree([
		"window\truns=10\tfailed_jobs=1\tnonverdict=1\tverdict=0\tunreadable=0",
		failure("111", "ci", "Run actions/checkout@3d3c42e"),
		"nonsense",
	])
}
