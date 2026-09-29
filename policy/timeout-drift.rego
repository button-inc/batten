# A job's committed timeout budget still matches measured reality (CLOUD-266,
# ported under CLOUD-1717, its producer retired into forge queries under
# CLOUD-843).
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
# WHAT IS READ, AND WHO DID WHICH HALF. Three families are recorded by
# `batten record query` from `[[forge.query]]` rows: `drift-runs` (each
# workflow's last successful runs, with the workflow's path) and `drift-jobs`
# (each run's jobs, with the duration in SECONDS the producer subtracted — no
# clock and no date parser reach this surface). The declared budgets are the
# workflows' own lines. Everything the retired shell body computed beyond the
# subtraction is here: which job a leg belongs to, the pooling of matrix legs,
# the p95, and the classification. CLOUD-1559: carry the decisions, not the steps.
#
# A SMALL SAMPLE REPORTS `unmeasurable`, NEVER A NUMBER, and that arm is load
# bearing rather than defensive. Ten of the fourteen jobs run weekly or on
# release, so a naive p95 over a two-week window would compute a confident value
# from two samples and propose tightening a release job on it. Below the declared
# minimum the job is reported as uncharacterised, which is itself the useful
# signal.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD. `record query` removes a family it could
# not read, so every rule below needs both families present. Reporting a healthy
# budget as drifted on a network blip is the failure mode that gets a scheduled
# gate switched off, and an absent record cannot do it.
#MUTANT-SUITE crates/batten/tests/it/timeout_drift.rs
#MUTANT loose-budget-passes|s@^\tentry.declared > entry.justified + slack$@\tfalse@|a_slack_budget_is_reported_as_loose_over_the_engines_projection
#MUTANT tight-budget-passes|s@^\tentry.declared < entry.justified$@\tfalse@|a_budget_the_measurement_has_outgrown_is_reported_as_tight
#MUTANT torn-census-passes|s@^\tcloses_of(input.tree.records\[family\]) != 1$@\tfalse@|a_census_that_did_not_finish_is_not_a_short_census
#MUTANT small-sample-yields-a-number|s@^\tentry.samples < minimum$@\tfalse@|a_job_with_too_few_samples_is_unmeasurable_rather_than_fast
#MUTANT matrix-legs-unpooled|s@^\tstartswith(name, concat("", \[key, " ("\]))$@\tfalse@|matrix_legs_pool_into_one_distribution
#MUTANT failed-leg-sampled|s@^\trow.conclusion == "success"$@\ttrue@|a_failed_leg_is_not_a_sample

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
# reads.
multiplier := 3

minimum := 5

slack := 5

# The two families the join needs. Both, or nothing is decided.
families := ["drift-runs", "drift-jobs"]

measured if {
	is_object(input.tree.records)
	input.tree.records["drift-runs"]
	input.tree.records["drift-jobs"]
}

rows_of(lines) := [row |
	some line in lines
	startswith(line, "row\t")
	row := json.unmarshal(trim_prefix(line, "row\t"))
]

closes_of(lines) := count([line |
	some line in lines
	startswith(line, "window\t")
])

# A FAMILY THAT DID NOT CLOSE IS NOT A SHORT FAMILY. `record query` writes a
# family whole or removes it, so a record present without exactly one closing
# line was torn by something other than the producer — present, so not
# could-not-look, and untrustworthy, so not clean.
torn contains family if {
	measured
	some family in families
	closes_of(input.tree.records[family]) != 1
}

violation contains {
	"rule": "bound measure partial",
	"verdict": "bound measure partial",
	"subjects": [{"artifact": family}, {"count": closes_of(input.tree.records[family])}],
} if {
	some family in torn
}

# Which workflow a run belongs to, by the path the forge reports for it.
run_paths := {row.id: row.path |
	measured
	some row in rows_of(input.tree.records["drift-runs"])
}

job_rows := rows_of(input.tree.records["drift-jobs"]) if measured

# --- the budgets, read off the workflows' own lines --------------------------
#
# The same walk `timeout-budget` takes, over the same `[[pattern]]` rows: a job
# key at two spaces below `jobs:`, and its job-level timeout at four.

workflow_paths contains path if {
	some path, _ in input.tree.lines
	startswith(path, ".github/workflows/")
}

jobs_header(path) := i if {
	some i, line in input.tree.lines[path]
	line == "jobs:"
}

job_key contains {"path": path, "line": i, "job": name} if {
	some path in workflow_paths
	some i, line in input.tree.lines[path]
	i > jobs_header(path)
	regex.match(data.batten.patterns["workflow-job-key"], line)
	not top_level_key_between(path, jobs_header(path), i)
	name := trim_space(substring(line, 0, indexof(line, ":")))
}

top_level_key_between(path, from, to) if {
	some k, line in input.tree.lines[path]
	k > from
	k < to
	regex.match(data.batten.patterns["workflow-top-level-key"], line)
}

owning_job(path, i) := row if {
	above := {k.line |
		some k in job_key
		k.path == path
		k.line < i
	}
	some row in job_key
	row.path == path
	row.line == max(above)
}

comment_of(line) := trim_space(substring(line, indexof(line, "#"), -1)) if {
	contains(line, "#")
}

comment_of(line) := "" if {
	not contains(line, "#")
}

basis_of(line) := "grandfathered" if {
	regex.match(data.batten.patterns["timeout-budget-grandfathered"], comment_of(line))
}

basis_of(line) := "measured" if {
	not regex.match(data.batten.patterns["timeout-budget-grandfathered"], comment_of(line))
}

budget contains {"path": path, "name": owning_job(path, i).job, "declared": declared, "basis": basis_of(line)} if {
	some path in workflow_paths
	some i, line in input.tree.lines[path]
	regex.match(data.batten.patterns["job-timeout-line"], line)
	value := trim_space(substring(line, indexof(line, ":") + 1, -1))
	declared := to_number(split(split(value, " ")[0], "#")[0])
}

# --- the measurement ---------------------------------------------------------

# MATRIX LEGS POOL. One `timeout-minutes` covers every leg of a matrix, and the
# forge reports each leg as `<key> (<axis>)`, so every leg feeds one
# distribution — matched on the job key, or the key followed by " (".
leg_of(name, key) if name == key

leg_of(name, key) if {
	startswith(name, concat("", [key, " ("]))
}

# A SUCCESSFUL leg's duration, and nothing else: a failed or cancelled leg ended
# early or late for a reason that is not the job's cost.
samples(path, key) := [row.seconds |
	some row in job_rows
	row.conclusion == "success"
	is_number(row.seconds)
	row.seconds >= 0
	run_paths[row.run] == path
	leg_of(row.name, key)
]

# The nearest-rank p95: the value at rank ceil(0.95 * n), counting from one.
p95(values) := 0 if count(values) == 0

p95(values) := sorted[ceil((95 * count(values)) / 100) - 1] if {
	count(values) > 0
	sorted := sort(values)
}

# `ceil(p95 * multiplier / 60)`, the same arithmetic `timeout-check` gates.
justified(seconds) := ceil((seconds * multiplier) / 60)

jobs contains entry if {
	measured
	some row in budget
	values := samples(row.path, row.name)
	entry := {
		"file": row.path,
		"name": row.name,
		"declared": row.declared,
		"justified": justified(p95(values)),
		"samples": count(values),
		"basis": row.basis,
	}
}

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

wf := ".github/workflows/ci.yml"

fixture_patterns := {
	"workflow-job-key": `^  [A-Za-z0-9_-]+:[[:space:]]*$`,
	"workflow-top-level-key": `^[a-z][A-Za-z0-9_-]*:`,
	"job-timeout-line": `^    timeout-minutes:[[:space:]]*[0-9]+`,
	"timeout-budget-grandfathered": `^#[[:space:]]*budget:[[:space:]]*grandfathered[[:space:]]+measured=[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$`,
}

comment(basis) := "# budget: grandfathered measured=2026-08-01" if basis == "grandfathered"

comment(basis) := "# budget: p95=40s x3 measured=2026-08-01" if basis == "measured"

run_row := "row\t{\"id\":1,\"path\":\".github/workflows/ci.yml\",\"workflow\":7}"

closed := "window\tstate=whole\tread=1\tkept=1\tmembers=1\ttruncated=0"

leg(name, conclusion, seconds) := sprintf(
	"row\t{\"conclusion\":\"%s\",\"name\":\"%s\",\"run\":1,\"seconds\":%d}",
	[conclusion, name, seconds],
)

# One workflow, one job `bats` with the declared budget, and `n` successful legs
# of `seconds` each.
tree(declared, basis, legs) := {"tree": {
	"lines": {wf: [
		"name: ci",
		"jobs:",
		"  bats:",
		"    runs-on: ubuntu-latest",
		sprintf("    timeout-minutes: %d %s", [declared, comment(basis)]),
	]},
	"records": {
		"drift-runs": [run_row, closed],
		"drift-jobs": array.concat(legs, [closed]),
	},
}}

legs(n, seconds) := [leg("bats", "success", seconds) | some _ in numbers.range(1, n)]

# `justified(120) == 6`, so a declared 6 is exactly right, 5 is tight, and 12 is
# loose once the five-minute slack is spent.
job(declared, seconds, n, basis) := tree(declared, basis, legs(n, seconds))

test_a_census_that_did_not_finish_is_not_a_short_census if {
	good := job(6, 120, 25, "measured")
	count(violation) == 0 with input as good with data.batten.patterns as fixture_patterns
	unclosed := object.union(good, {"tree": {"records": {"drift-jobs": legs(25, 120)}}})
	some v in violation with input as unclosed with data.batten.patterns as fixture_patterns
	v.subjects == [{"artifact": "drift-jobs"}, {"count": 0}]
}

test_a_budget_matching_its_measurement_is_clean if {
	count(violation) == 0 with input as job(6, 120, 25, "measured") with data.batten.patterns as fixture_patterns
}

test_a_slack_budget_is_reported_as_loose if {
	some v in violation with input as job(12, 120, 25, "measured") with data.batten.patterns as fixture_patterns
	v.verdict == "bound pin loose"
}

# THE SLACK IS A BOUNDARY, not a suggestion: at exactly `justified + slack` the
# budget is still correct, because a ceiling is allowed headroom.
test_a_budget_inside_the_slack_is_not_loose if {
	count(violation) == 0 with input as job(11, 120, 25, "measured") with data.batten.patterns as fixture_patterns
}

test_a_budget_the_measurement_has_outgrown_is_reported_as_tight if {
	some v in violation with input as job(5, 120, 25, "measured") with data.batten.patterns as fixture_patterns
	v.verdict == "bound pin wrong"
}

# POINTER, NEVER PAYLOAD: the job's name and the minutes the measurement
# justifies, which is what the remedy needs and nothing more.
test_the_report_carries_a_name_and_a_count if {
	some v in violation with input as job(12, 120, 25, "measured") with data.batten.patterns as fixture_patterns
	v.subjects == [{"artifact": "bats"}, {"count": 6}]
}

test_a_job_with_too_few_samples_is_unmeasurable_rather_than_fast if {
	some v in violation with input as job(30, 120, 2, "measured") with data.batten.patterns as fixture_patterns
	v.verdict == "bound measure partial"
}

# AND IT IS THE ONLY REPORT for that job.
test_an_unmeasurable_job_is_not_also_classified if {
	count(violation) == 1 with input as job(30, 120, 2, "measured") with data.batten.patterns as fixture_patterns
}

test_a_grandfathered_entry_with_samples_is_a_conversion_prompt if {
	some v in violation with input as job(30, 120, 25, "grandfathered") with data.batten.patterns as fixture_patterns
	v.verdict == "bound pin stale"
}

test_a_grandfathered_entry_is_not_also_drift if {
	count(violation) == 1 with input as job(30, 120, 25, "grandfathered") with data.batten.patterns as fixture_patterns
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}, "lines": {wf: ["jobs:", "  bats:", "    timeout-minutes: 30"]}}} with data.batten.patterns as fixture_patterns
}

# THE p95 IS NEAREST-RANK: over twenty samples of 60s and two of 600s the p95 is
# 600 (rank 21 of 22), so a declared 6 is tight against a justified 30.
test_the_p95_is_the_nearest_rank_over_the_pooled_samples if {
	slow := array.concat(legs(20, 60), legs(2, 600))
	some v in violation with input as tree(6, "measured", slow) with data.batten.patterns as fixture_patterns
	v.subjects == [{"artifact": "bats"}, {"count": 30}]
}

test_matrix_legs_pool_into_one_distribution if {
	pooled := array.concat(
		[leg("bats (ubuntu-latest)", "success", 120) | some _ in numbers.range(1, 3)],
		[leg("bats (macos-latest)", "success", 120) | some _ in numbers.range(1, 3)],
	)
	count(violation) == 0 with input as tree(6, "measured", pooled) with data.batten.patterns as fixture_patterns
}

test_a_failed_leg_is_not_a_sample if {
	failed := array.concat(legs(4, 120), [leg("bats", "failure", 120)])
	some v in violation with input as tree(6, "measured", failed) with data.batten.patterns as fixture_patterns
	v.subjects == [{"artifact": "bats"}, {"count": 4}]
}

# A LEG FROM ANOTHER WORKFLOW'S RUN IS NOT THIS JOB'S, even under the same key.
test_a_leg_from_another_workflows_run_is_not_counted if {
	other := [sprintf("row\t{\"conclusion\":\"success\",\"name\":\"bats\",\"run\":2,\"seconds\":%d}", [120]) | some _ in numbers.range(1, 25)]
	some v in violation with input as tree(6, "measured", other) with data.batten.patterns as fixture_patterns
	v.verdict == "bound measure partial"
}
