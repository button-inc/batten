# METADATA
# description: |
#   A report task stays off the landing path — CLOUD-582, ported from
#   `mise-tasks/report-only-check.sh` under CLOUD-843.
#
#   Two tasks here are REPORTS rather than gates, `coverage` (CLOUD-111) and
#   `scorecard`, and both were non-gates by a decision no exit code held. Each
#   carries a long comment saying so, which is feedforward with no sensor: the
#   whole of what kept them off the landing path was that nobody added them.
#
#   THE FAILURE IS QUIET AND ONE-DIRECTIONAL. Adding a report to `verify` or to a
#   `pull_request` workflow makes it a gate, and it then fails a branch for a
#   NUMBER — a coverage percentage, or a scorecard check counting a deliberate
#   design decision as a defect. That is the model-verdict shape non-negotiable
#   rule 3 refuses, arriving as a one-line diff nobody reads as a policy change.
#
#   NOT PART OF `ci-local-parity`, which parses the same two inputs. That gate
#   asserts the FORWARD direction — every task CI runs is one `verify` runs. This
#   is the INVERSE: the named tasks appear in neither. Composing them would give
#   one task two properties that fail for opposite reasons, and the deny would
#   have to explain which.
#
#   WHICH TASKS, AND WHY THE LIST LIVES HERE. A report is not a syntactic
#   category — nothing in a task's declaration says "this emits a number nobody
#   may block on" — so the set is a judgement, made once, written where the gate
#   enforcing it can be read beside it. Adding a name is a decision to keep it off
#   the landing path forever; removing one is a decision to allow it on, and both
#   are visible in the same diff as the gate. This is a consumer module, so the
#   consumer's own judgement belongs in it.
#
#   THE SCHEDULE IS THE POINT, NOT A VIOLATION. Only the `pull_request` trigger is
#   judged: a scheduled workflow running a report is why the report exists.
#
#   THE SUCCESSOR READS PARSED DOCUMENTS WHERE THE SHELL READ TEXT, and that is
#   strictly better rather than merely different. The predecessor carved
#   `[tasks.verify]`'s span out of `mise.toml` with awk and then word-bounded a
#   grep so `coverage` was not satisfied by `COVERAGE_OUT_DIR`. A parsed document
#   has no span to carve and no boundary to get right: `depends` is a list of
#   task names and the body is a string, so a name either IS an entry or appears
#   in the text, and the two are asked separately.
#
#   Pointer-only (non-negotiable rule 4): the task name and where it was found,
#   never the matched line.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.report_only

import rego.v1

rules contains "report-only"

manifest := "mise.toml"

# The consumer's judgement, written beside the gate that enforces it.
reports := {"coverage", "scorecard"}

verify := task if {
	task := input.tree.documents[manifest].tasks.verify
}

# THE COULD-NOT-LOOK ARM. No `[tasks.verify]` means there is nothing to judge a
# report against, and reporting that as clean would be the false green the
# predecessor spent an explicit exit 2 on.
violation contains {
	"rule": "report-only",
	"verdict": "task guard missing",
	"subjects": [{"path": manifest}],
} if {
	input.tree.documents[manifest]
	not verify
}

# A report named in `verify`'s own `depends` list.
violation contains {
	"rule": "report-only",
	"verdict": "task judge silent",
	"subjects": [{"path": manifest}],
} if {
	some task in reports
	some named in verify.depends
	named == task
}

# Or reached from its body. A string rather than a list, so this is a text
# question — and it is the one the predecessor's `COVERAGE_OUT_DIR` case is
# about: the invocation is what makes it a gate, so the spelling that counts is
# `mise run <task>` rather than the bare name.
violation contains {
	"rule": "report-only",
	"verdict": "task judge silent",
	"subjects": [{"path": manifest}],
} if {
	some task in reports
	contains(verify.run, sprintf("mise run %s", [task]))
}

# The other way onto the landing path, and the one `verify` cannot see.
violation contains {
	"rule": "report-only",
	"verdict": "task judge silent",
	"subjects": [{"path": path}],
} if {
	some path, doc in input.tree.documents
	startswith(path, ".github/workflows/")
	doc.on.pull_request
	some _, job in doc.jobs
	some step in job.steps
	some task in reports
	contains(step.run, sprintf("mise run %s", [task]))
}

# --- the load-time tier ------------------------------------------------------

verify_task(task) := {"tree": {"documents": {"mise.toml": {"tasks": {"verify": task}}}}}

test_a_clean_manifest_passes if {
	count(violation) == 0 with input as verify_task({"depends": ["ci"], "run": "mise run land-divergence"})
}

test_a_report_in_verifys_depends_is_refused if {
	some v in violation with input as verify_task({"depends": ["ci", "coverage"], "run": ""})
	v.verdict == "task judge silent"
}

test_a_report_invoked_by_verifys_body_is_refused if {
	count(violation) == 1 with input as verify_task({"depends": ["ci"], "run": "mise run scorecard"})
}

# THE BOUNDARY CASE the predecessor word-bounded a grep for. A parsed `depends`
# is a list of names, so a longer identifier is simply a different entry.
test_a_longer_identifier_merely_containing_the_name_does_not_fire if {
	count(violation) == 0 with input as verify_task({
		"depends": ["coverage-report-check"],
		"run": "echo $COVERAGE_OUT_DIR",
	})
}

test_no_verify_task_is_could_not_look if {
	some v in violation with input as {"tree": {"documents": {"mise.toml": {"tasks": {}}}}}
	v.verdict == "task guard missing"
}

workflow(trigger, run) := {"tree": {"documents": {
	"mise.toml": {"tasks": {"verify": {"depends": ["ci"], "run": ""}}},
	".github/workflows/report.yml": {"on": trigger, "jobs": {"j": {"steps": [{"run": run}]}}},
}}}

test_a_report_run_on_pull_request_is_refused if {
	some v in violation with input as workflow({"pull_request": {}}, "mise run coverage")
	v.verdict == "task judge silent"
}

# A SCHEDULED workflow running a report is the whole point of the report.
test_a_report_run_on_a_schedule_is_the_point_not_a_violation if {
	count(violation) == 0 with input as workflow({"schedule": [{"cron": "0 0 * * 0"}]}, "mise run coverage")
}

#MUTANT-SUITE crates/batten/tests/it/report_only.rs
#MUTANT report-on-pull-request-passes|s@workflow.on.pull_request@true@|a_report_run_on_a_schedule_is_the_point_not_a_violation
#MUTANT report-in-depends-unread|s@named == task@false@|a_report_in_verifys_depends_is_refused_over_the_binary
#MUTANT report-no-verify-unread|s@not verify$@false@|no_verify_task_is_could_not_look
