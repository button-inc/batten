# A step a CI job carves out must be run by a job that does (CLOUD-1140).
#
# THE DEFECT THIS EXISTS FOR, and it is one `hook-profile-check` structurally
# cannot see. That gate reads `hk check --all --plan` and asserts every
# `slow`-tagged step is `included` there — the false green it names is "the slow
# tier stops running under `check`, so clippy, the test suite and `batten-check`
# silently vanish from CI". It reads `.claude/hooks/git-hook.sh`'s invocation
# line for the economy half, because a plan cannot tell you what a CALLER passes.
#
# CLOUD-1140 adds a second caller with exactly that shape. The `ci` job now sets
# `HK_SKIP_STEPS: test:bats` so the shell suite runs on its own runner instead of
# serialising behind the cargo chain — 83% of a step that was 92% of a job that
# was the whole critical path. The plan `hook-profile-check` reads is unchanged
# by that env var, so the suite could be carved out of the `ci` job and run
# nowhere at all, and every gate in this repository would be green over a suite
# that never executed. That is the `profiled-step-not-in-check` class one layer
# up, where its own gate cannot reach.
#
# THE ASYMMETRY IS THE WHOLE DESIGN, and it is why this is a deny rather than a
# report. The two ways the pairing comes apart are not equally visible:
#
#   * a name here that no step matches — the step runs in BOTH jobs. Wasteful,
#     and it shows up in the bill and in the wall clock.
#   * a name here that no job runs — the step runs in NEITHER. Nothing is red,
#     nothing is slower, and the gate is simply gone.
#
# So the predicate is stated over the second direction: every name a job skips
# must be a name some job in the same workflow runs. The first direction needs no
# gate because it has a symptom.
#
# LINES ARE NOT ENOUGH AND THE PARSED DOCUMENT IS, which is why this reads
# `input.tree.documents` rather than scanning text. `HK_SKIP_STEPS` and the
# `mise run` that answers it are in different jobs, tens of lines apart, and a
# line-oriented reading cannot say which job either belongs to — the question is
# structural. `bats-invocation` already reads this same workflow as a parsed
# document for its `install_args` clause, so the shape is established here.
#
#MUTANT-SUITE crates/batten/tests/it/ci_suite_lane.rs
#MUTANT governance-unread|s@^\tgoverned$@\tfalse@|a_carved_out_step_no_job_runs_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_suite_lane

import rego.v1

rules contains "ci-suite-lane"

# --- what is being judged, and whether there is anything to judge -------------

workflow_path := ".github/workflows/ci.yml"

workflow := input.tree.documents[workflow_path]

# The guard, and the reason this rule does not fire on a foreign tree: a
# repository with no such workflow is answering for nothing. `hk-fix-selection`
# records the measured lesson — an unguarded module reported seven findings
# against a fixture that carried a copy of the config and none of its subjects.
governed if count(object.keys(workflow.jobs)) > 0

# --- the two sides of the pairing ---------------------------------------------

# EVERY NAME ANY JOB CARVES OUT. Read at both the step and the job level, because
# GitHub honours the variable in either place and a reading that covered only one
# would answer "no skips" about a workflow that skips at the other — a silent
# pass, which is the direction this rule exists to refuse.
#
# Comma-split because hk takes a list there. A single name splits to itself, so
# the common case costs nothing and the list case is not a second spelling.
skipped_names contains name if {
	some _, job in workflow.jobs
	some step in job.steps
	raw := step.env.HK_SKIP_STEPS
	some part in split(raw, ",")
	name := trim_space(part)
	name != ""
}

skipped_names contains name if {
	some _, job in workflow.jobs
	raw := job.env.HK_SKIP_STEPS
	some part in split(raw, ",")
	name := trim_space(part)
	name != ""
}

# EVERY TASK ANY JOB IN THIS WORKFLOW RUNS, as the `run:` scalars carry it. The
# same reading `ci-local-parity` property 3 uses on the other side of the same
# question: the steps, never the prose, because these files carry long comments
# that name tasks in order to explain why they are ABSENT, and a gate that fires
# on its own documentation is a gate people delete.
run_bodies contains body if {
	some _, job in workflow.jobs
	some step in job.steps
	body := step.run
}

runs_task(name) if {
	some body in run_bodies
	contains(body, concat("", ["mise run ", name]))
}

# --- the refusal ---------------------------------------------------------------

violation contains {
	"rule": "ci-suite-lane",
	"verdict": "gate skip unseen",
	"subjects": [{"path": workflow_path}, {"artifact": name}],
} if {
	governed
	some name in skipped_names
	not runs_task(name)
}

# --- could not look -----------------------------------------------------------

# A DECLARED SOURCE THAT WOULD NOT PARSE is not an absent one. Absent is
# not-applicable — this tree runs no such workflow — and unparsed means the
# boundary tried and failed. Spelling those the same way is how a gate reports
# green over a file it never read.
violation contains {
	"rule": "ci-suite-lane",
	"verdict": "workflow read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	path == workflow_path
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# the document these rules read, which is `crates/batten/tests/ci_suite_lane.rs`'s
# job and the reason that file exists.

sound_input(jobs) := {"tree": {
	"documents": {".github/workflows/ci.yml": {"jobs": jobs}},
	"missing": {},
}}

paired_jobs := {
	"ci": {"steps": [{
		"run": "mise run ci",
		"env": {"HK_SKIP_STEPS": "test:bats", "DOCTOR_TARGETS": ""},
	}]},
	"bats": {"steps": [{"run": "mise run test:bats", "env": {"DOCTOR_TARGETS": ""}}]},
}

test_a_skipped_step_another_job_runs_is_clean if {
	found := violation with input as sound_input(paired_jobs)
	count(found) == 0
}

# THE DEFECT ITSELF: the carve-out stayed and the job that answered it went. This
# is the shape that is green everywhere else in the repository.
test_a_skipped_step_no_job_runs_is_refused if {
	found := violation with input as sound_input({"ci": paired_jobs.ci})
	count(found) == 1
	some finding in found
	finding.verdict == "gate skip unseen"
	some subject in finding.subjects
	subject.artifact == "test:bats"
}

# THE LIST FORM, so a second name added to the variable cannot ride in on the
# first one's coverage.
test_only_the_uncovered_name_of_a_list_is_reported if {
	jobs := {
		"ci": {"steps": [{"run": "mise run ci", "env": {"HK_SKIP_STEPS": "test:bats,sbom-check"}}]},
		"bats": {"steps": [{"run": "mise run test:bats"}]},
	}
	found := violation with input as sound_input(jobs)
	count(found) == 1
	some finding in found
	some subject in finding.subjects
	subject.artifact == "sbom-check"
}

# JOB-LEVEL ENV IS THE SAME QUESTION. Reading only the step level would answer
# "nothing is skipped" about a workflow that skips, which is the silent pass.
test_a_job_level_carve_out_is_read_too if {
	jobs := {"ci": {
		"env": {"HK_SKIP_STEPS": "test:bats"},
		"steps": [{"run": "mise run ci"}],
	}}
	found := violation with input as sound_input(jobs)
	count(found) == 1
	some finding in found
	finding.verdict == "gate skip unseen"
}

# ANTI-VACUITY'S OTHER HALF: a workflow that carves nothing out has nothing to
# answer for, and must not be confused with one whose skips are all covered.
test_a_workflow_that_skips_nothing_is_clean if {
	found := violation with input as sound_input({"ci": {"steps": [{"run": "mise run ci"}]}})
	count(found) == 0
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT.
test_a_tree_with_no_such_workflow_is_not_this_rules_business if {
	found := violation with input as {"tree": {"documents": {}, "missing": {}}}
	count(found) == 0
}

# COULD NOT LOOK STAYS LOUD, and is spelled differently from both of the above.
test_an_unreadable_workflow_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"missing": {".github/workflows/ci.yml": "absent"},
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "workflow read unread"
}
