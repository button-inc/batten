# METADATA
# description: |
#   Every workflow job's timeout carries a budget comment that justifies it —
#   CLOUD-266, ported from `mise-tasks/timeout-check.sh` under CLOUD-843.
#
#   Every job here already declares a timeout, so the ABSENCE of a limit was never
#   the problem. The problem is that the numbers are boilerplate: one value for
#   anything substantial, a smaller one for anything small, and no number derived
#   from what its job costs. Measured over 25 runs, the headroom over p95 ranged
#   from 3.4x to 75x.
#
#   A cap at 75x of measured behaviour is not a limit. It cannot fail a job that is
#   merely broken-slow, only one that is fully wedged, and it does so after burning
#   the full budget. More to the point it is inert as FEEDBACK: a job could double
#   and every gate would stay green, so the number never tells anyone that CI got
#   slower. A budget that only fires on catastrophe is a smoke alarm, not a
#   thermostat.
#
#   So this does not check the LIMIT. It checks that the limit is JUSTIFIED, and
#   makes the absence of a justification visible and unremovable.
#
#   THE BUDGET LIVES BESIDE THE VALUE IT BOUNDS, as a trailing comment on the same
#   line, in one of exactly two forms — a grandfathered one carrying only a
#   measurement date, and a measured one carrying a p95, a multiplier and a date. A
#   separate table would be a second file to hold in agreement with ten workflows,
#   and a budget that can drift from the enforced value without failing is the
#   second authority non-negotiable rule 6 warns about. Beside-the-value also
#   handles the one structural oddity for free: a matrix job whose single timeout
#   covers several legs, which a table would have needed a key scheme to express.
#
#   GRANDFATHERED IS NOT A SYNONYM FOR EXEMPT. It means "this value predates
#   measurement and nobody has justified it yet" — honest, gateable, and visibly
#   not a justification, so it reads as DEBT rather than as a decision.
#
#   THE MULTIPLIER IS ONE REPOSITORY-WIDE CONSTANT rather than a per-job field. A
#   per-job multiplier is a per-job argument; the point of a single number is that
#   loosening it anywhere is visible as loosening it everywhere.
#
#   WHAT THIS DELIBERATELY DOES NOT DO: it never asks whether a budget still
#   matches reality. That is a property of the world, not of the commit, and it
#   belongs on a clock — the same split the lock-completeness and lock-currency
#   pair sets.
#
#   THE JOB LEVEL IS THE INDENT. The timeout is anchored at exactly four spaces. A
#   step-level timeout sits deeper and is the step's business; matching it here
#   would let a step satisfy a job's obligation.
#
#   WHY THIS IS A MODULE NOW AND WAS NOT A ROW BEFORE. The retiring program asked
#   the question and answered it honestly: the predicate is "this key's value
#   equals an ARITHMETIC FUNCTION of a number in an adjacent comment", a `forbid`
#   row matches a literal substring and cannot compare integers, and the absent
#   capability was a numeric comparison over a parsed field. A policy module is
#   exactly that capability, and non-negotiable rule 1 still holds because the
#   arithmetic lives in this consumer's own module rather than in the engine.
#
#   POINTER, NEVER PAYLOAD (rule 4): the workflow, the line, the job and the
#   declared value — never the workflow body.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.timeout_budget

import rego.v1

rules contains "timeout-budget"

# The one repository-wide headroom multiplier a measured budget is derived with.
budget_multiplier := 3

workflow_paths contains path if {
	some path, _ in input.tree.lines
	startswith(path, ".github/workflows/")
}

lines_of(path) := input.tree.lines[path]

# --- the job walker ----------------------------------------------------------

jobs_header(path) := i if {
	some i, line in lines_of(path)
	line == "jobs:"
}

# A job key at exactly two spaces, below the header and above the next top-level
# key.
job_key contains {"path": path, "line": i, "job": name} if {
	some path in workflow_paths
	some i, line in lines_of(path)
	i > jobs_header(path)
	regex.match(data.batten.patterns["workflow-job-key"], line)
	not top_level_key_between(path, jobs_header(path), i)
	name := trim_space(substring(line, 0, indexof(line, ":")))
}

top_level_key_between(path, from, to) if {
	some k, line in lines_of(path)
	k > from
	k < to
	regex.match(data.batten.patterns["workflow-top-level-key"], line)
}

# The job a line belongs to: the nearest job key above it.
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

# A timeout at exactly four spaces — job level.
timeout contains {"path": path, "line": i, "job": owning_job(path, i).job, "declared": declared, "comment": comment_of(line)} if {
	some path in workflow_paths
	some i, line in lines_of(path)
	regex.match(data.batten.patterns["job-timeout-line"], line)
	value := trim_space(substring(line, indexof(line, ":") + 1, -1))
	declared := to_number(split(split(value, " ")[0], "#")[0])
}

comment_of(line) := trim_space(substring(line, indexof(line, "#"), -1)) if {
	contains(line, "#")
}

comment_of(line) := "" if {
	not contains(line, "#")
}

jobs_with_timeouts contains sprintf("%s:%d", [row.path, row.line]) if {
	some row in timeout
	some k in job_key
	k.path == row.path
	k.job == row.job
	row.line > k.line
}

# --- the could-not-look arms -------------------------------------------------
#
# A workflow this cannot parse as a workflow is not a workflow with no jobs, and
# a silent pass over it is the failure this arm exists for.
violation contains {
	"rule": "timeout-budget",
	"verdict": "job list empty",
	"subjects": [{"path": path}],
} if {
	some path in workflow_paths
	not jobs_header(path)
}

violation contains {
	"rule": "timeout-budget",
	"verdict": "job list empty",
	"subjects": [{"path": path}],
} if {
	some path in workflow_paths
	jobs_header(path)
	count({k | some k in job_key; k.path == path}) == 0
}

# --- the four findings -------------------------------------------------------
#
# The job's OWN line is carried where there is no timeout to point at: a pointer
# to the top of the file is a pointer a reader cannot act on.
#
# THE JOB NAME IS IN THE POINTER RATHER THAN BESIDE IT, which is the retiring
# program's own `<path>:<line> <job>` shape and not a stylistic choice: a finding
# renders its FIRST subject, so a job name in a second one is a pointer the reader
# never sees.
violation contains {
	"rule": "timeout-budget",
	"verdict": "timer declare missing",
	"subjects": [{"artifact": sprintf("%s:%d %s", [k.path, k.line + 1, k.job])}],
} if {
	some k in job_key
	not job_has_timeout(k)
}

job_has_timeout(k) if {
	some row in timeout
	row.path == k.path
	row.job == k.job
}

violation contains {
	"rule": "timeout-budget",
	"verdict": "timer carry unnamed",
	"subjects": [{"artifact": sprintf("%s:%d %s", [row.path, row.line + 1, row.job])}],
} if {
	some row in timeout
	row.comment == ""
}

violation contains {
	"rule": "timeout-budget",
	"verdict": "timer parse unclear",
	"subjects": [{"artifact": sprintf("%s:%d %s", [row.path, row.line + 1, row.job])}],
} if {
	some row in timeout
	row.comment != ""
	not grandfathered(row)
	not measured(row)
}

grandfathered(row) if {
	regex.match(data.batten.patterns["timeout-budget-grandfathered"], row.comment)
}

measured(row) if {
	count(regex.find_all_string_submatch_n(data.batten.patterns["timeout-budget-measured"], row.comment, 1)) == 1
}

groups(row) := regex.find_all_string_submatch_n(data.batten.patterns["timeout-budget-measured"], row.comment, 1)[0]

# The multiplier is one repository-wide constant: a per-job one is a per-job
# argument.
violation contains {
	"rule": "timeout-budget",
	"verdict": "timer count other",
	"subjects": [{"artifact": sprintf("%s:%d %s", [row.path, row.line + 1, row.job])}],
} if {
	some row in timeout
	measured(row)
	to_number(groups(row)[2]) != budget_multiplier
}

# `ceil(p95 x multiplier / 60)`, in integer arithmetic.
expected_minutes(p95, multiplier) := floor(((p95 * multiplier) + 59) / 60)

violation contains {
	"rule": "timeout-budget",
	"verdict": "timer count wrong",
	"subjects": [{"artifact": sprintf("%s:%d %s", [row.path, row.line + 1, row.job])}],
} if {
	some row in timeout
	measured(row)
	to_number(groups(row)[2]) == budget_multiplier
	row.declared != expected_minutes(to_number(groups(row)[1]), budget_multiplier)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE — the walker, the two grammars and the arithmetic. They
# cannot pin that the ENGINE resolves a declared `line_sources` GLOB over every
# workflow (CLOUD-845), and this rule's declared SCOPE is exactly that: every
# workflow including the scheduled and release ones, which is the hole it fills.
# A resolution reaching only some of them would leave the most expensive job here
# unbounded with nothing red. `crates/batten/tests/it/timeout_budget.rs` is that
# tier.

flow(jobs) := {"tree": {"lines": {".github/workflows/ci.yml": array.concat(["on: push", "jobs:"], jobs)}}}

test_a_grandfathered_budget_is_clean if {
	count(violation) == 0 with input as flow([
		"  build:",
		"    timeout-minutes: 15 # budget: grandfathered measured=2026-08-01",
	])
}

test_a_measured_budget_whose_arithmetic_holds_is_clean if {
	count(violation) == 0 with input as flow([
		"  build:",
		"    timeout-minutes: 14 # budget: p95=267s x3 measured=2026-08-01",
	])
}

test_a_job_with_no_timeout_is_refused if {
	some v in violation with input as flow(["  build:", "    runs-on: ubuntu-latest"])
	v.verdict == "timer declare missing"
}

test_a_timeout_with_no_budget_comment_is_refused if {
	some v in violation with input as flow(["  build:", "    timeout-minutes: 15"])
	v.verdict == "timer carry unnamed"
}

# A comment that merely mentions the word is not a budget: the grammars are
# matched whole.
test_a_malformed_budget_is_refused if {
	some v in violation with input as flow([
		"  build:",
		"    timeout-minutes: 15 # budget is generous here",
	])
	v.verdict == "timer parse unclear"
}

test_arithmetic_that_disagrees_with_its_own_p95_is_refused if {
	some v in violation with input as flow([
		"  build:",
		"    timeout-minutes: 30 # budget: p95=267s x3 measured=2026-08-01",
	])
	v.verdict == "timer count wrong"
}

# The multiplier is one repository-wide constant, so loosening it anywhere is
# visible as loosening it everywhere.
test_a_per_job_multiplier_is_refused if {
	some v in violation with input as flow([
		"  build:",
		"    timeout-minutes: 45 # budget: p95=267s x10 measured=2026-08-01",
	])
	v.verdict == "timer count other"
}

# A STEP-level timeout sits deeper and is the step's business; matching it here
# would let a step satisfy the job's obligation.
test_a_step_timeout_does_not_satisfy_the_jobs_obligation if {
	some v in violation with input as flow([
		"  build:",
		"    steps:",
		"      - run: make",
		"        timeout-minutes: 5 # budget: grandfathered measured=2026-08-01",
	])
	v.verdict == "timer declare missing"
}

# Every job is judged, not only the first.
test_a_second_job_is_judged_too if {
	some v in violation with input as flow([
		"  build:",
		"    timeout-minutes: 15 # budget: grandfathered measured=2026-08-01",
		"  publish:",
		"    timeout-minutes: 15",
	])
	v.verdict == "timer carry unnamed"
}

# A file this cannot parse as a workflow is not a workflow with no jobs.
test_a_workflow_with_no_jobs_block_is_could_not_look if {
	some v in violation with input as {"tree": {"lines": {".github/workflows/ci.yml": ["on: push", "name: ci"]}}}
	v.verdict == "job list empty"
}

test_a_jobs_block_with_no_job_keys_is_could_not_look if {
	some v in violation with input as flow(["  # every job was removed"])
	v.verdict == "job list empty"
}

#MUTANT-SUITE crates/batten/tests/it/timeout_budget.rs
#MUTANT budgetless-timeout-passes|s@^\tnot job_has_timeout(k)$@\tfalse@|a_job_with_no_timeout_is_refused
#MUTANT unbudgeted-timeout-passes|s@^\trow.comment == ""$@\tfalse@|a_timeout_with_no_budget_comment_is_refused
#MUTANT arithmetic-unchecked|s@^\trow.declared != expected_minutes(to_number(groups(row)\[1\]), budget_multiplier)$@\tfalse@|arithmetic_that_disagrees_with_its_own_p95_is_refused
