# CI signal: a job's committed timeout budget still matches measured reality
# (CLOUD-266, ported under CLOUD-1717, its producer retired into forge queries
# and its decision moved out of a consumer module into this preset under
# CLOUD-843).
#
# REPORT, NEVER GATE, and the enabling row's severity is the whole of that. A
# gate asking whether every timeout is JUSTIFIED is a question about the commit
# and belongs on the landing path. This asks whether the justification is still
# TRUE, which is a question about the world and changes with no diff, so the
# consumer enables it at `warn` and runs it `--fail-on-warning` on a schedule.
#
# DRIFT IS REPORTED IN BOTH DIRECTIONS, and the loose direction is the point. A
# budget gone slack because the job got faster is the ratchet this exists for; a
# report that only complained about tightness would let every number rot upward
# forever.
#
# WHAT IS READ, AND WHO DID WHICH HALF. Two record families, written by
# `batten record query` from the consumer's own `[[forge.query]]` rows under the
# names this preset reads: `drift-runs` (each workflow's recent successful runs,
# `id` and `path`) and `drift-jobs` (each run's jobs, `name`, `conclusion`, the
# member `run` and a `seconds` span the producer subtracted — no clock and no
# date parser reach this surface). Which endpoints, which windows and which
# credential are the consumer's rows; the family names and row keys are this
# preset's contract, as `ci-signal`'s siblings fix theirs. The budgets are the
# workflows' own lines, handed over by the row's `line_sources`. Everything else
# is here: which job a leg belongs to, the pooling of matrix legs, the p95 and
# the classification. CLOUD-1559: carry the decisions, not the steps.
#
# A SMALL SAMPLE REPORTS `unmeasurable`, NEVER A NUMBER, and that arm is load
# bearing rather than defensive. Jobs that run weekly or on release have a
# handful of runs in any window, so a naive p95 would compute a confident value
# from two samples and propose tightening a release job on it. Below the minimum
# the job is reported as uncharacterised, which is itself the useful signal.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD. `record query` removes a family it could
# not read, so every rule below needs both families present. Reporting a healthy
# budget as drifted on a network blip is the failure mode that gets a scheduled
# gate switched off, and an absent record cannot do it.
#
# GITHUB ACTIONS' GRAMMAR, AND NOTHING OF ANY ONE REPOSITORY'S. The job key at two
# spaces under `jobs:`, the job-level `timeout-minutes:` at four, and a matrix
# leg reported as `<key> (<axis>)` are the provider's; the manifest declares the
# provider so a consumer elsewhere is refused at load rather than judged clean.
# The literals are inline rather than `[[pattern]]` rows because a preset
# reaches a consumer who wrote none (`rules/policy-modules.md`), and the manifest
# lists the ids they would be.
#
# EVERY NAME IS PREFIXED `drift_`: a preset's modules share one `package`, and
# its siblings bind their own shapes under `lane_` and `job_`.
#MUTANT-SUITE crates/batten/tests/it/timeout_drift.rs
#MUTANT loose-budget-passes|s@^\tentry.declared > entry.justified + drift_slack$@\tfalse@|a_slack_budget_is_reported_as_loose_over_the_engines_projection
#MUTANT tight-budget-passes|s@^\tentry.declared < entry.justified$@\tfalse@|a_budget_the_measurement_has_outgrown_is_reported_as_tight
#MUTANT torn-census-passes|s@^\tdrift_closes_of(input.tree.records\[family\]) != 1$@\tfalse@|a_census_that_did_not_finish_is_not_a_short_census
#MUTANT small-sample-yields-a-number|s@^\tentry.samples < drift_minimum$@\tfalse@|a_job_with_too_few_samples_is_unmeasurable_rather_than_fast
#MUTANT matrix-legs-unpooled|s@^\tstartswith(name, concat("", \[key, " ("\]))$@\tfalse@|matrix_legs_pool_into_one_distribution
#MUTANT failed-leg-sampled|s@^\trow.conclusion == "success"$@\ttrue@|a_failed_leg_is_not_a_sample

# METADATA
# description: |
#   Bound to the TREE surface: the enabling row is `scope = "tree"`, so this
#   reads `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_signal

import rego.v1

rules contains "bound pin loose"

rules contains "bound pin wrong"

rules contains "bound pin stale"

rules contains "bound measure partial"

# The headroom multiplier a justified budget carries over its p95, and the two
# thresholds the retired program carried as knobs.
#
# IN THE MODULE RATHER THAN IN CONFIG: these are the practice's own figures, and
# a config knob invites raising them until nothing is ever reported. Moving one
# costs a diff a reviewer reads.
drift_multiplier := 3

drift_minimum := 5

drift_slack := 5

# The provider's grammar, inline for the reason the header gives. The `[[pattern]]`
# ids these would be are `workflow-job-key`, `workflow-top-level-key`,
# `job-timeout-line` and `timeout-budget-grandfathered`.
drift_job_key_line := `^  [A-Za-z0-9_-]+:[[:space:]]*$`

drift_top_level_key_line := `^[a-z][A-Za-z0-9_-]*:`

drift_timeout_line := `^    timeout-minutes:[[:space:]]*[0-9]+`

# The one convention this preset adds to the grammar: a budget nobody has
# measured yet carries a dated debt marker in its own comment, and is prompted
# for conversion once a sample exists rather than classified as drift.
drift_grandfathered_comment := `^#[[:space:]]*budget:[[:space:]]*grandfathered[[:space:]]+measured=[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$`

# The two families the join needs. Both, or nothing is decided.
drift_families := ["drift-runs", "drift-jobs"]

drift_measured if {
	is_object(input.tree.records)
	input.tree.records["drift-runs"]
	input.tree.records["drift-jobs"]
}

drift_rows_of(lines) := [row |
	some line in lines
	startswith(line, "row\t")
	row := json.unmarshal(trim_prefix(line, "row\t"))
]

drift_closes_of(lines) := count([line |
	some line in lines
	startswith(line, "window\t")
])

# A FAMILY THAT DID NOT CLOSE IS NOT A SHORT FAMILY. `record query` writes a
# family whole or removes it, so a record present without exactly one closing
# line was torn by something other than the producer — present, so not
# could-not-look, and untrustworthy, so not clean.
drift_torn contains family if {
	drift_measured
	some family in drift_families
	drift_closes_of(input.tree.records[family]) != 1
}

violation contains {
	"rule": "bound measure partial",
	"verdict": "bound measure partial",
	"subjects": [{"artifact": family}, {"count": drift_closes_of(input.tree.records[family])}],
} if {
	some family in drift_torn
}

# Which workflow a run belongs to, by the path the forge reports for it.
drift_run_paths := {row.id: row.path |
	drift_measured
	some row in drift_rows_of(input.tree.records["drift-runs"])
}

drift_job_rows := drift_rows_of(input.tree.records["drift-jobs"]) if drift_measured

# --- the budgets, read off the workflows' own lines --------------------------
#
# Every document the row hands over that HAS a `jobs:` mapping; which files
# those are is the row's `line_sources`, never a path spelled here.

drift_jobs_header(path) := i if {
	some i, line in input.tree.lines[path]
	line == "jobs:"
}

drift_job_key contains {"path": path, "line": i, "job": name} if {
	some path, lines in input.tree.lines
	some i, line in lines
	i > drift_jobs_header(path)
	regex.match(drift_job_key_line, line)
	not drift_top_level_key_between(path, drift_jobs_header(path), i)
	name := trim_space(substring(line, 0, indexof(line, ":")))
}

drift_top_level_key_between(path, from, to) if {
	some k, line in input.tree.lines[path]
	k > from
	k < to
	regex.match(drift_top_level_key_line, line)
}

drift_owning_job(path, i) := row if {
	above := {k.line |
		some k in drift_job_key
		k.path == path
		k.line < i
	}
	some row in drift_job_key
	row.path == path
	row.line == max(above)
}

drift_comment_of(line) := trim_space(substring(line, indexof(line, "#"), -1)) if {
	contains(line, "#")
}

drift_comment_of(line) := "" if {
	not contains(line, "#")
}

drift_basis_of(line) := "grandfathered" if {
	regex.match(drift_grandfathered_comment, drift_comment_of(line))
}

drift_basis_of(line) := "measured" if {
	not regex.match(drift_grandfathered_comment, drift_comment_of(line))
}

drift_budget contains {"path": path, "name": drift_owning_job(path, i).job, "declared": declared, "basis": drift_basis_of(line)} if {
	some path, lines in input.tree.lines
	some i, line in lines
	regex.match(drift_timeout_line, line)
	value := trim_space(substring(line, indexof(line, ":") + 1, -1))
	declared := to_number(split(split(value, " ")[0], "#")[0])
}

# --- the measurement ---------------------------------------------------------

# MATRIX LEGS POOL. One `timeout-minutes` covers every leg of a matrix, and the
# forge reports each leg as `<key> (<axis>)`, so every leg feeds one
# distribution — matched on the job key, or the key followed by " (".
drift_leg_of(name, key) if name == key

drift_leg_of(name, key) if {
	startswith(name, concat("", [key, " ("]))
}

# A SUCCESSFUL leg's duration, and nothing else: a failed or cancelled leg ended
# early or late for a reason that is not the job's cost.
drift_samples(path, key) := [row.seconds |
	some row in drift_job_rows
	row.conclusion == "success"
	is_number(row.seconds)
	row.seconds >= 0
	drift_run_paths[row.run] == path
	drift_leg_of(row.name, key)
]

# The nearest-rank p95: the value at rank ceil(0.95 * n), counting from one.
drift_p95(values) := 0 if count(values) == 0

drift_p95(values) := sorted[ceil((95 * count(values)) / 100) - 1] if {
	count(values) > 0
	sorted := sort(values)
}

# `ceil(p95 * multiplier / 60)`, in whole minutes.
drift_justified(seconds) := ceil((seconds * drift_multiplier) / 60)

drift_jobs contains entry if {
	drift_measured
	some row in drift_budget
	values := drift_samples(row.path, row.name)
	entry := {
		"file": row.path,
		"name": row.name,
		"declared": row.declared,
		"justified": drift_justified(drift_p95(values)),
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
	some entry in drift_jobs
	entry.samples < drift_minimum
}

# THE DEBT ENTRY THAT CAN NOW BE CONVERTED. This is the prompt, never the
# conversion: a bot re-baselining the number it is supposed to defend is the one
# move a budget exists to forbid.
violation contains {
	"rule": "bound pin stale",
	"verdict": "bound pin stale",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in drift_jobs
	entry.samples >= drift_minimum
	entry.basis == "grandfathered"
}

# THE NUMBER THE MEASUREMENT HAS OUTGROWN — raise it before it starts failing
# healthy runs.
violation contains {
	"rule": "bound pin wrong",
	"verdict": "bound pin wrong",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in drift_jobs
	entry.samples >= drift_minimum
	entry.basis == "measured"
	entry.declared < entry.justified
}

# THE NUMBER THAT HAS GONE SLACK. A budget is a ceiling rather than a target, so
# some headroom is correct and `drift_slack` is what keeps this off every job
# that merely got a little faster.
violation contains {
	"rule": "bound pin loose",
	"verdict": "bound pin loose",
	"subjects": [{"artifact": entry.name}, {"count": entry.justified}],
} if {
	some entry in drift_jobs
	entry.samples >= drift_minimum
	entry.basis == "measured"
	entry.declared > entry.justified + drift_slack
}

# --- cases ---------------------------------------------------------------
#
# NO `data.batten` FIXTURE ANYWHERE BELOW, and that absence is the preset's own
# case: a consumer who wrote no `[[pattern]]` rows is exactly who this reaches.

drift_wf := "workflows/ci.yml"

drift_comment(basis) := "# budget: grandfathered measured=2026-08-01" if basis == "grandfathered"

drift_comment(basis) := "# budget: p95=40s x3 measured=2026-08-01" if basis == "measured"

drift_run_row := "row\t{\"id\":1,\"path\":\"workflows/ci.yml\",\"workflow\":7}"

drift_closed := "window\tstate=whole\tread=1\tkept=1\tmembers=1\ttruncated=0"

drift_leg(name, conclusion, seconds) := sprintf(
	"row\t{\"conclusion\":\"%s\",\"name\":\"%s\",\"run\":1,\"seconds\":%d}",
	[conclusion, name, seconds],
)

# One workflow, one job `bats` with the declared budget, and the given legs. The
# path is deliberately not the provider's usual directory: which files hold
# budgets is the row's `line_sources`, never this module's.
drift_tree(declared, basis, legs) := {"tree": {
	"lines": {drift_wf: [
		"name: ci",
		"jobs:",
		"  bats:",
		"    runs-on: ubuntu-latest",
		sprintf("    timeout-minutes: %d %s", [declared, drift_comment(basis)]),
	]},
	"records": {
		"drift-runs": [drift_run_row, drift_closed],
		"drift-jobs": array.concat(legs, [drift_closed]),
	},
}}

drift_legs(n, seconds) := [drift_leg("bats", "success", seconds) | some _ in numbers.range(1, n)]

# `drift_justified(120) == 6`, so a declared 6 is exactly right, 5 is tight, and
# 12 is loose once the five-minute slack is spent.
drift_job(declared, seconds, n, basis) := drift_tree(declared, basis, drift_legs(n, seconds))

test_drift_a_census_that_did_not_finish_is_not_a_short_census if {
	good := drift_job(6, 120, 25, "measured")
	count(violation) == 0 with input as good
	unclosed := object.union(good, {"tree": {"records": {"drift-jobs": drift_legs(25, 120)}}})
	some v in violation with input as unclosed
	v.subjects == [{"artifact": "drift-jobs"}, {"count": 0}]
}

test_drift_a_budget_matching_its_measurement_is_clean if {
	count(violation) == 0 with input as drift_job(6, 120, 25, "measured")
}

test_drift_a_slack_budget_is_reported_as_loose if {
	some v in violation with input as drift_job(12, 120, 25, "measured")
	v.verdict == "bound pin loose"
}

# THE SLACK IS A BOUNDARY, not a suggestion: at exactly `justified + slack` the
# budget is still correct, because a ceiling is allowed headroom.
test_drift_a_budget_inside_the_slack_is_not_loose if {
	count(violation) == 0 with input as drift_job(11, 120, 25, "measured")
}

test_drift_a_budget_the_measurement_has_outgrown_is_reported_as_tight if {
	some v in violation with input as drift_job(5, 120, 25, "measured")
	v.verdict == "bound pin wrong"
}

# POINTER, NEVER PAYLOAD: the job's name and the minutes the measurement
# justifies, which is what the remedy needs and nothing more.
test_drift_the_report_carries_a_name_and_a_count if {
	some v in violation with input as drift_job(12, 120, 25, "measured")
	v.subjects == [{"artifact": "bats"}, {"count": 6}]
}

test_drift_a_job_with_too_few_samples_is_unmeasurable_rather_than_fast if {
	some v in violation with input as drift_job(30, 120, 2, "measured")
	v.verdict == "bound measure partial"
}

# AND IT IS THE ONLY REPORT for that job.
test_drift_an_unmeasurable_job_is_not_also_classified if {
	count(violation) == 1 with input as drift_job(30, 120, 2, "measured")
}

test_drift_a_grandfathered_entry_with_samples_is_a_conversion_prompt if {
	some v in violation with input as drift_job(30, 120, 25, "grandfathered")
	v.verdict == "bound pin stale"
}

test_drift_a_grandfathered_entry_is_not_also_drift if {
	count(violation) == 1 with input as drift_job(30, 120, 25, "grandfathered")
}

test_drift_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}, "lines": {drift_wf: ["jobs:", "  bats:", "    timeout-minutes: 30"]}}}
}

# THE p95 IS NEAREST-RANK: over twenty samples of 60s and two of 600s the p95 is
# 600 (rank 21 of 22), so a declared 6 is tight against a justified 30.
test_drift_the_p95_is_the_nearest_rank_over_the_pooled_samples if {
	slow := array.concat(drift_legs(20, 60), drift_legs(2, 600))
	some v in violation with input as drift_tree(6, "measured", slow)
	v.subjects == [{"artifact": "bats"}, {"count": 30}]
}

test_drift_matrix_legs_pool_into_one_distribution if {
	pooled := array.concat(
		[drift_leg("bats (ubuntu-latest)", "success", 120) | some _ in numbers.range(1, 3)],
		[drift_leg("bats (macos-latest)", "success", 120) | some _ in numbers.range(1, 3)],
	)
	count(violation) == 0 with input as drift_tree(6, "measured", pooled)
}

test_drift_a_failed_leg_is_not_a_sample if {
	failed := array.concat(drift_legs(4, 120), [drift_leg("bats", "failure", 120)])
	some v in violation with input as drift_tree(6, "measured", failed)
	v.subjects == [{"artifact": "bats"}, {"count": 4}]
}

# A LEG FROM ANOTHER WORKFLOW'S RUN IS NOT THIS JOB'S, even under the same key.
test_drift_a_leg_from_another_workflows_run_is_not_counted if {
	other := [sprintf("row\t{\"conclusion\":\"success\",\"name\":\"bats\",\"run\":2,\"seconds\":%d}", [120]) | some _ in numbers.range(1, 25)]
	some v in violation with input as drift_tree(6, "measured", other)
	v.verdict == "bound measure partial"
}

# A DOCUMENT WITH NO `jobs:` MAPPING DECLARES NO BUDGET, whatever its lines look
# like: an indented `timeout-minutes:` outside a job is not a job's.
test_drift_a_document_without_jobs_declares_no_budget if {
	stray := object.union(drift_job(12, 120, 25, "measured"), {"tree": {"lines": {drift_wf: ["name: ci", "    timeout-minutes: 12"]}}})
	count(violation) == 0 with input as stray
}
