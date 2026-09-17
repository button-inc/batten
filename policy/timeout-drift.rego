# A job's committed timeout budget still matches measured reality (CLOUD-266,
# ported under CLOUD-1717).
#
# REPORT, NEVER GATE, and the severity is the whole of that. `timeout-check` asks
# a question about the COMMIT — is every timeout justified — and belongs on the
# landing path. This asks whether the justification is still TRUE, which is a
# question about the world and changes with no diff. The retired program said so
# by failing only its own scheduled run: no issue filed, no comment posted,
# nothing blocked. `severity = "warn"` is that posture expressed on the engine's
# contract — a warn finding is reported without failing the run.
#
# DRIFT IS REPORTED IN BOTH DIRECTIONS, and the loose direction is the point. A
# budget gone slack because the job got faster is the ratchet the row exists for;
# a report that only complained about tightness would let every number rot upward
# forever.
#
# WHY THE MEASUREMENT STAYS OUTSIDE. The samples are durations of successful runs
# read from the Actions API, and the p95 over them is arithmetic over instants —
# two things this surface cannot do. §5 makes `check` `read` and incapable of
# spawning, and `Fact::Instant` projects `null` to every module, which
# `clippy.toml`'s `disallowed-methods` and `crates/batten/tests/clock_ban.rs` hold
# the engine to. So `[tasks.timeout-drift-record]` reads the runs, subtracts the
# instants, computes the p95 and records a row per job; the classification — which
# is the decision — is here. CLOUD-1559: carry the decisions, not the steps.
#
# A SMALL SAMPLE REPORTS `unmeasurable`, NEVER A NUMBER, and that arm is load
# bearing rather than defensive. Ten of the fourteen jobs run weekly or on
# release, so a naive p95 over a two-week window would compute a confident value
# from two samples and propose tightening a release job on it. Below the declared
# minimum the job is reported as uncharacterised, which is itself the useful
# signal.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD. Every exit-2 arm of the retired program — no
# `gh`, a query that would not answer, an unreadable workflow directory — is now
# the producer refusing at write time and writing nothing. Reporting a healthy
# budget as drifted on a network blip is the failure mode that gets a scheduled
# gate switched off, and an absent record cannot do it.
#MUTANT-SUITE crates/batten/tests/it/timeout_drift.rs
#MUTANT loose-budget-passes|s@^\tentry.declared > (entry.justified + slack)$@\tfalse@|a_slack_budget_is_reported_as_loose_over_the_engines_projection
#MUTANT tight-budget-passes|s@^\tentry.declared < entry.justified$@\tfalse@|a_budget_the_measurement_has_outgrown_is_reported_as_tight
#MUTANT small-sample-yields-a-number|s@^\tentry.samples < minimum$@\tfalse@|a_job_with_too_few_samples_is_unmeasurable_rather_than_fast

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.timeout_drift

import rego.v1

rules contains "bound pin loose"

rules contains "bound pin wrong"

rules contains "bound pin stale"

rules contains "bound measure partial"

# The repo-wide headroom multiplier `timeout-check` gates, and the two thresholds
# the retired program carried as knobs.
#
# IN THE MODULE RATHER THAN IN CONFIG, on `repetition-without-progress`'s
# reasoning: these are the practice's own figures, and a config knob invites
# raising them until nothing is ever reported. Moving one costs a diff a reviewer
# reads. The retired program took them from the environment, which is how a
# scheduled report ends up measured against numbers nobody chose — its own
# `fail_input` arm existed because a typo'd knob read as a working setting.
multiplier := 3

minimum := 5

slack := 5

# The producer's lines, or nothing.
recorded := input.tree.records["timeout-drift"]

# `job <file> <name> <declared-minutes> <p95-seconds> <samples> <basis>` — one per
# job the producer characterised. `basis` is `measured` or `grandfathered`: a dated
# debt entry that now HAS a usable sample is a different report from a number that
# has drifted, because the remedy is to convert it rather than to move it.
jobs contains entry if {
	some raw in recorded
	columns := split(raw, "\t")
	count(columns) == 7
	columns[0] == "job"
	regex.match(data.batten.patterns["whole-number"], columns[3])
	regex.match(data.batten.patterns["whole-number"], columns[4])
	regex.match(data.batten.patterns["whole-number"], columns[5])
	entry := {
		"file": columns[1],
		"name": columns[2],
		"declared": to_number(columns[3]),
		"justified": justified(to_number(columns[4])),
		"samples": to_number(columns[5]),
		"basis": columns[6],
	}
}

# `ceil(p95 * multiplier / 60)`, the same arithmetic `timeout-check` gates.
#
# `ceil` RATHER THAN THE SHELL'S `(x + 59) / 60`, and the difference is not
# cosmetic: that idiom is integer division, and Rego's `/` is float — carrying it
# over verbatim would make `justified(120)` 6.98 rather than 6, so every
# comparison below would read against a number no budget can equal. The shell's
# arithmetic is a STEP; what carries is the decision it computed.
justified(p95) := ceil((p95 * multiplier) / 60)

# A JOB NOBODY CAN CHARACTERISE, reported first because the arms below would
# otherwise compute a confident classification from two samples.
violation contains {
	"rule": "bound measure partial",
	"verdict": "bound measure partial",
	"subjects": [{"artifact": entry.name}, {"count": entry.samples}],
} if {
	some entry in jobs
	entry.samples < minimum
}

# THE DEBT ENTRY THAT CAN NOW BE CONVERTED. This is the prompt, never the
# conversion: a bot re-baselining the number it is supposed to defend is the one
# move §4 forbids outright.
violation contains {
	"rule": "bound pin stale",
	"verdict": "bound pin stale",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in jobs
	entry.samples >= minimum
	entry.basis == "grandfathered"
}

# THE NUMBER THE MEASUREMENT HAS OUTGROWN — raise it before it starts failing
# healthy runs.
violation contains {
	"rule": "bound pin wrong",
	"verdict": "bound pin wrong",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in jobs
	entry.samples >= minimum
	entry.basis == "measured"
	entry.declared < entry.justified
}

# THE NUMBER THAT HAS GONE SLACK. A budget is a ceiling rather than a target, so
# some headroom is correct and `slack` is what keeps this off every job that
# merely got a little faster.
violation contains {
	"rule": "bound pin loose",
	"verdict": "bound pin loose",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in jobs
	entry.samples >= minimum
	entry.basis == "measured"
	entry.declared > entry.justified + slack
}

# --- cases ---------------------------------------------------------------

tree(lines) := {"tree": {"records": {"timeout-drift": lines}}}

# `justified(120) == 6`, so a declared 6 is exactly right, 5 is tight, and 12 is
# loose once the five-minute slack is spent.
job(declared, p95, samples, basis) := tree([sprintf(
	"job\tci.yml\tbats\t%d\t%d\t%d\t%s",
	[declared, p95, samples, basis],
)])

test_a_budget_matching_its_measurement_is_clean if {
	count(violation) == 0 with input as job(6, 120, 25, "measured")
}

test_a_slack_budget_is_reported_as_loose if {
	some v in violation with input as job(12, 120, 25, "measured")
	v.verdict == "bound pin loose"
}

# THE SLACK IS A BOUNDARY, not a suggestion: at exactly `justified + slack` the
# budget is still correct, because a ceiling is allowed headroom.
test_a_budget_inside_the_slack_is_not_loose if {
	count(violation) == 0 with input as job(11, 120, 25, "measured")
}

test_a_budget_the_measurement_has_outgrown_is_reported_as_tight if {
	some v in violation with input as job(5, 120, 25, "measured")
	v.verdict == "bound pin wrong"
}

# POINTER, NEVER PAYLOAD: the job's name and the minutes the measurement
# justifies, which is what the remedy needs and nothing more.
test_the_report_carries_a_name_and_a_count if {
	some v in violation with input as job(12, 120, 25, "measured")
	v.subjects == [{"artifact": "bats"}, {"count": 6}]
}

test_a_job_with_too_few_samples_is_unmeasurable_rather_than_fast if {
	some v in violation with input as job(30, 120, 2, "measured")
	v.verdict == "bound measure partial"
}

# AND IT IS THE ONLY REPORT for that job: a classification computed from two
# samples is the confident-and-wrong answer the arm exists to prevent, so a slack
# budget must not ALSO be reported as loose here.
test_an_unmeasurable_job_is_not_also_classified if {
	count(violation) == 1 with input as job(30, 120, 2, "measured")
}

test_a_grandfathered_entry_with_samples_is_a_conversion_prompt if {
	some v in violation with input as job(30, 120, 25, "grandfathered")
	v.verdict == "bound pin stale"
}

# A GRANDFATHERED ENTRY IS NOT ALSO DRIFT. Its remedy is to convert the debt to a
# measured budget, and reporting it as loose as well would send the reader to move
# a number they are supposed to replace.
test_a_grandfathered_entry_is_not_also_drift if {
	count(violation) == 1 with input as job(30, 120, 25, "grandfathered")
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A LINE THIS READER CANNOT PARSE IS SKIPPED — the producer refuses a malformed
# line at write time, so an unparseable one at read time is a torn store. The
# surviving good line keeps this from passing for want of any readable row.
test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as tree([
		"job\tci.yml\tbats\t6\t120\t25\tmeasured",
		"job\tci.yml\tbroken\tnot-a-number\t120\t25\tmeasured",
		"nonsense",
	])
}
