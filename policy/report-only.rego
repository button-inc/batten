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

rules contains "gate report silent"

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
	"rule": "gate report silent",
	"verdict": "task guard missing",
	"subjects": [{"path": manifest}],
} if {
	input.tree.documents[manifest]
	not verify
}

# A report named in `verify`'s own `depends` list.
violation contains {
	"rule": "gate report silent",
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
# **THE TASK NAME IS MATCHED WHOLE** (review of #928). Both clauses below used a
# bare `contains(..., "mise run <task>")`, so `mise run coverage-report-check`
# read as `mise run coverage` and a gate that judges was reported as a report that
# does not — a false violation on a `deny` row, which is the direction that gets
# a gate switched off rather than fixed.
#
# The terminator set, not a character class: the `[[pattern]]` rule refuses an
# inline regex and a pattern row cannot carry a needle that is a different task
# every iteration. These are what actually follow a task name in this tree — an
# argument, the end of a shell string, a chained command, a subshell close — and
# a name ENDING the text is the other arm, for the reason `dead-capability`'s
# `reached` now carries.
TASK_TAIL := {" ", "\"", "'", "`", ";", "&", ")", "\n"}

invokes_task(text, task) if {
	some tail in TASK_TAIL
	contains(text, concat("", ["mise run ", task, tail]))
}

invokes_task(text, task) if {
	endswith(trim_space(text), concat("", ["mise run ", task]))
}

# **EVERY FORM OF THE TRIGGER** (review of #928). `doc.on.pull_request` matches
# only the MAPPING form, because the YAML parser renders a mapping as an object,
# a sequence as an array and a scalar as a string. So `on: [push, pull_request]`
# and `on: pull_request` each ran a report on the landing path with nothing said.
#
# `pull_request_target` is deliberately NOT accepted: this rule is scoped to
# `pull_request` by the module's own header, and the two triggers differ in what
# they grant rather than in when they fire.
on_pull_request(doc) if doc.on.pull_request

on_pull_request(doc) if {
	is_array(doc.on)
	"pull_request" in doc.on
}

on_pull_request(doc) if doc.on == "pull_request"

violation contains {
	"rule": "gate report silent",
	"verdict": "task judge silent",
	"subjects": [{"path": manifest}],
} if {
	some task in reports
	invokes_task(verify.run, task)
}

# The other way onto the landing path, and the one `verify` cannot see.
violation contains {
	"rule": "gate report silent",
	"verdict": "task judge silent",
	"subjects": [{"path": path}],
} if {
	some path, doc in input.tree.documents
	startswith(path, ".github/workflows/")
	on_pull_request(doc)
	some _, job in doc.jobs
	some step in job.steps
	some task in reports
	invokes_task(step.run, task)
}

# --- the load-time tier ------------------------------------------------------

verify_task(task) := {"tree": {"documents": {"mise.toml": {"tasks": {"verify": task}}}}}

test_a_clean_manifest_passes if {
	count(violation) == 0 with input as verify_task({"depends": ["ci"], "run": "mise run land-divergence"})
}

# **A LONGER NAME IS A DIFFERENT TASK** (review of #928). `mise run coverage`
# used to match inside `mise run coverage-report-check`, so a gate that judges
# was reported as a report that does not. Both clauses are covered: the manifest
# one here and the workflow one below.
test_a_longer_task_name_is_not_the_report if {
	count(violation) == 0 with input as verify_task({"depends": [], "run": "mise run coverage-report-check"})
}

test_the_report_itself_is_still_refused_in_the_run if {
	some v in violation with input as verify_task({"depends": [], "run": "mise run coverage"})
	v.verdict == "task judge silent"
}

# AND A NAME ENDING THE STRING IS STILL A CALL, which is the other unbounded
# position — the residue `dead-capability`'s `reached` paid for three times.
test_a_report_ending_the_run_string_is_refused if {
	some v in violation with input as verify_task({"depends": [], "run": "cd x && mise run scorecard"})
	v.verdict == "task judge silent"
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

# **THE LIST AND SCALAR TRIGGER FORMS** (review of #928). The parser renders a
# mapping as an object, a sequence as an array and a scalar as a string, and only
# the first matched — so these two ran a report on the landing path with nothing
# said.
test_a_report_run_on_a_pull_request_listed_in_a_sequence_is_refused if {
	some v in violation with input as workflow(["push", "pull_request"], "mise run coverage")
	v.verdict == "task judge silent"
}

test_a_report_run_on_a_bare_pull_request_scalar_is_refused if {
	some v in violation with input as workflow("pull_request", "mise run coverage")
	v.verdict == "task judge silent"
}

# AND A SEQUENCE THAT DOES NOT NAME IT IS STILL NOT THE LANDING PATH, so the two
# arms above widen the trigger reading without widening the verdict.
test_a_sequence_without_pull_request_is_not_refused if {
	count(violation) == 0 with input as workflow(["push", "workflow_dispatch"], "mise run coverage")
}

# THE WORKFLOW CLAUSE GETS THE NAME BOUNDARY TOO, not just the manifest one.
test_a_longer_task_name_in_a_workflow_step_is_not_the_report if {
	count(violation) == 0 with input as workflow({"pull_request": {}}, "mise run coverage-report-check")
}

# A SCHEDULED workflow running a report is the whole point of the report.
test_a_report_run_on_a_schedule_is_the_point_not_a_violation if {
	count(violation) == 0 with input as workflow({"schedule": [{"cron": "0 0 * * 0"}]}, "mise run coverage")
}

#MUTANT-SUITE crates/batten/tests/it/report_only.rs
# THE TARGET NAMED A PATTERN THIS MODULE DOES NOT CONTAIN (review of #928): the
# arm reads `doc.on`, never `workflow.on`, so the sed matched nothing and the
# mutation was a no-op reported as caught — a survivor wearing a pass. The
# catcher is the case that actually reddens when the trigger test stops deciding.
#MUTANT report-on-pull-request-passes|s@^\ton_pull_request(doc)$@\ttrue@|a_report_run_on_a_schedule_is_the_point_not_a_violation
#MUTANT report-in-depends-unread|s@named == task@false@|a_report_in_verifys_depends_is_refused_over_the_binary
#MUTANT report-no-verify-unread|s@not verify$@false@|no_verify_task_is_could_not_look
