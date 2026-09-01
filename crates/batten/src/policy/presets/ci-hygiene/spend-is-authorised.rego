#MUTANT-SUITE crates/batten/tests/it/ci_hygiene.rs
#MUTANT draft-gate-unread|s@^\tnot job_is_draft_gated(path, name)$@\tfalse@|a_job_that_runs_on_a_draft_is_refused_and_named
# CI spends nothing the author could have spent for free (CLOUD-1161).
#
# Four properties about what a hosted-CI run COSTS, each computable over the
# committed workflow text alone: no network, no run history, no judgement.
#
#   1. NO JOB RUNS ON A DRAFT. Draft means "still being verified locally", and it
#      is also the lever a red run pulls: a lander that re-drafts a pull request
#      stops further spend while the failure is diagnosed. A single job missing
#      the guard defeats both.
#
#   2. EVERY `pull_request` WORKFLOW SUPERSEDES ITS OWN RUNS. A landing lap
#      rebases and pushes; without `cancel-in-progress` the superseded commit's
#      run is paid out in full for a verdict nobody reads. It is also what lets a
#      lander cancel a doomed run by pushing the next one rather than calling the
#      forge's cancel endpoint.
#
#   3. EVERY WORKFLOW DECLARES A CONCURRENCY GROUP. Property 2 is the landing
#      path's half of this and was the whole of it in the program this replaces,
#      which is why eleven workflows in the measured tree had none: it is guarded
#      on `pull_request`, and a comment- or schedule-triggered workflow never
#      reaches that guard. The two arms are NOT one — a pull-request workflow
#      supersedes itself, a scheduled one must NOT be killed by its own next tick
#      — so declaring a group is all this asks of every workflow.
#
#   4. A DRAFT-GATED WORKFLOW SUBSCRIBES TO `ready_for_review`. Omitting `types:`
#      defaults to `[opened, synchronize, reopened]`. Where property 1 holds,
#      a pull request created as a draft mints a skipped run on `opened`, and with
#      no `ready_for_review` there is no event left that could replace it: a
#      waiter correctly refuses to read a skip as an answer and polls forever.
#      Measured as a deadlock across two pull requests at once, both fully green
#      but for one such name.
#
#      SCOPED TO WORKFLOWS THAT DRAFT-GATE, which is what makes it a preset
#      rather than a repository's rule. The program this replaces scoped it to
#      "produces a required check", and a required-check roster is a consumer's
#      fact. Draft-gating is the same condition read from the workflow itself: a
#      job that skips on a draft is a job whose verdict can only arrive on the
#      ready event.
#
# Names no repository, no directory, no task and no job: every one of these is
# true of the practice, which is what a vendored preset may contain
# (non-negotiable rule 1). The consumer's `sources` glob decides which workflows
# are judged.

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_hygiene

import rego.v1

rules contains "no-job-runs-on-a-draft"

rules contains "pull-request-workflow-supersedes-itself"

rules contains "workflow-declares-a-concurrency-group"

rules contains "draft-gated-workflow-subscribes-to-ready"

# --- what counts as a workflow this rule may judge ----------------------------
#
# A parsed document carrying a `jobs` mapping. The guard matters for the reason
# `hk-fix-selection` records: an unguarded module reported seven findings against
# a fixture that carried a copy of the config and none of its subjects. A tree
# with no such document is answering for nothing.
workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

# `on:` SURVIVES THE PARSE AS THE STRING KEY, and that is measured rather than
# assumed. YAML 1.1 resolves a bare `on` to a boolean, which would key this block
# as `true` and make every predicate below a dead gate — the class where a module
# passes its own suite green while deciding nothing. The parser this engine uses
# resolves only `true`/`false` as booleans, so `on` arrives as written; the
# compiled-binary tier is what proves it over real YAML rather than over a
# fabricated document.
#
# The scalar form (`on: push`) yields a string rather than a mapping, so
# `triggers` simply does not hold for it and every predicate keyed on a named
# trigger stands down. That is the honest reading: a workflow written that way
# declares no `types:` and no branch filter to judge.
triggers(path) := t if {
	t := workflow[path].on
	is_object(t)
}

on_pull_request(path) if _ := triggers(path).pull_request

# --- 1. no job runs on a draft ------------------------------------------------

# The guard, wherever the job carries it. Read at the JOB level and at each STEP,
# because a workflow may gate the whole job or gate the steps that spend, and a
# reading that covered only one would report a guarded workflow as unguarded —
# a false refusal, which is how a gate gets switched off.
draft_guard := "github.event.pull_request.draft == false"

job_is_draft_gated(path, name) if contains(workflow[path].jobs[name]["if"], draft_guard)

job_is_draft_gated(path, name) if {
	some step in workflow[path].jobs[name].steps
	contains(step["if"], draft_guard)
}

violation contains {
	"rule": "no-job-runs-on-a-draft",
	"verdict": "V-JOB-RUNS-ON-DRAFT",
	"subjects": [{"path": path}, {"artifact": name}],
} if {
	some path, _ in workflow
	on_pull_request(path)
	some name, _ in workflow[path].jobs
	not job_is_draft_gated(path, name)
}

# --- 2. a pull-request workflow supersedes its own runs -----------------------

# `cancel-in-progress` arrives as a BOOLEAN, not the string `"true"`, because the
# parser resolves it. The program this replaces matched the text `cancel-in-progress: true`;
# comparing against `true` here is the same predicate over a parsed document, and
# writing it as a string comparison would be a dead gate.
supersedes_itself(path) if workflow[path].concurrency["cancel-in-progress"] == true

violation contains {
	"rule": "pull-request-workflow-supersedes-itself",
	"verdict": "V-PR-WORKFLOW-NOT-SUPERSEDED",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	on_pull_request(path)
	not supersedes_itself(path)
}

# --- 3. every workflow declares a concurrency group ---------------------------
#
# Only the group's EXISTENCE is asked for here; the value is rule 2's, because
# the right value differs by trigger and a single answer is wrong for one of
# them. A scheduled workflow must not cancel its own previous tick.

declares_concurrency(path) if _ := workflow[path].concurrency

# SCOPED TO TRIGGERS WHOSE RUNS ANSWER ABOUT ONE SUBJECT, and the distinction is
# the whole correctness of the rule rather than a convenience.
#
# Under `pull_request`, `issue_comment`, `workflow_run` and `schedule`, two runs
# in flight are two answers to the SAME question — the same pull request, the
# same comment thread, the same upstream run, the same recurring job — so
# overlapping them is at best waste and at worst a race. Measured: N concurrent
# comment invocations ran N concurrent attempts to advance a trunk branch, at 245
# refusals against 6 merges in half an hour.
#
# A `push`-only workflow is the one case where that does not hold: each run is
# keyed to a DIFFERENT commit, so two runs are two subjects rather than two
# answers, and superseding is a cost preference rather than a correctness
# property. Demanding a group there would make this rule refuse an ordinary
# minimal repository — which is a real cost for a preset that ships to every
# consumer, and which this repository's own shipped-config canary
# (`tests/prebuilt-lint.bats`, whose fixture carries the committed ruleset and
# asserts a minimal tree is clean) is what surfaced.
races_itself(path) if {
	some trigger in ["pull_request", "issue_comment", "workflow_run", "schedule"]
	_ := triggers(path)[trigger]
}

violation contains {
	"rule": "workflow-declares-a-concurrency-group",
	"verdict": "V-WORKFLOW-NO-CONCURRENCY",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	races_itself(path)
	not declares_concurrency(path)
}

# --- 4. a draft-gated workflow subscribes to ready_for_review -----------------

draft_gates_anything(path) if {
	some name, _ in workflow[path].jobs
	job_is_draft_gated(path, name)
}

# The `pull_request` trigger's own `types:`, never the whole `on:` block: a
# `types:` belonging to another trigger says nothing about this one, and reading
# the block as a whole would let one satisfy the other.
subscribes_to_ready(path) if {
	some kind in triggers(path).pull_request.types
	kind == "ready_for_review"
}

violation contains {
	"rule": "draft-gated-workflow-subscribes-to-ready",
	"verdict": "V-READY-FOR-REVIEW-UNSUBSCRIBED",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	on_pull_request(path)
	draft_gates_anything(path)
	not subscribes_to_ready(path)
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# the document these rules read, which is `crates/batten/tests/ci_hygiene.rs`'s
# job and the reason that file exists.

sound := {"tree": {"documents": {".github/workflows/ci.yml": {
	"on": {"pull_request": {"types": ["opened", "synchronize", "reopened", "ready_for_review"]}},
	"concurrency": {"group": "ci-${{ github.ref }}", "cancel-in-progress": true},
	"jobs": {"build": {
		"if": "${{ github.event.pull_request.draft == false }}",
		"steps": [{"run": "make"}],
	}},
}}}}

with_workflow(doc) := {"tree": {"documents": {".github/workflows/ci.yml": doc}}}

test_a_guarded_superseding_workflow_is_clean if {
	count(violation) == 0 with input as sound
}

# SPELLED OUT RATHER THAN MERGED, and that is measured rather than stylistic:
# `object.union` is a DEEP merge, so removing a key by overriding its parent
# keeps it. Both of this file's first-draft removal fixtures were silently
# identical to the clean one, and the two deny cases passed nothing.
test_an_ungated_job_is_refused_and_named if {
	doc := {
		"on": {"pull_request": {"types": ["opened", "ready_for_review"]}},
		"concurrency": {"group": "ci", "cancel-in-progress": true},
		"jobs": {"build": {"steps": [{"run": "make"}]}},
	}
	found := violation with input as with_workflow(doc)
	count(found) == 1
	some f in found
	f.verdict == "V-JOB-RUNS-ON-DRAFT"
	some s in f.subjects
	s.artifact == "build"
}

# A STEP-LEVEL GUARD COUNTS. Reading only the job level would refuse a workflow
# that is correctly gated, and a gate that refuses its own remedy gets deleted.
test_a_step_level_guard_is_read_too if {
	doc := object.union(sound.tree.documents[".github/workflows/ci.yml"], {"jobs": {"build": {"steps": [{
		"run": "make",
		"if": "${{ github.event.pull_request.draft == false }}",
	}]}}})
	count(violation) == 0 with input as with_workflow(doc)
}

test_a_workflow_that_never_supersedes_is_refused if {
	doc := {
		"on": {"pull_request": {"types": ["opened", "ready_for_review"]}},
		"concurrency": {"group": "ci"},
		"jobs": {"build": {
			"if": "${{ github.event.pull_request.draft == false }}",
			"steps": [{"run": "make"}],
		}},
	}
	found := violation with input as with_workflow(doc)
	count(found) == 1
	some f in found
	f.verdict == "V-PR-WORKFLOW-NOT-SUPERSEDED"
}

# THE STRING SPELLING IS NOT THE VALUE. A parsed `true` is a boolean, so a module
# comparing against `"true"` would be green here and dead in the field.
test_a_quoted_cancel_flag_is_not_the_boolean if {
	doc := object.union(sound.tree.documents[".github/workflows/ci.yml"], {"concurrency": {"group": "ci", "cancel-in-progress": "true"}})
	found := violation with input as with_workflow(doc)
	count(found) == 1
	some f in found
	f.verdict == "V-PR-WORKFLOW-NOT-SUPERSEDED"
}

test_a_workflow_with_no_concurrency_at_all_is_refused if {
	doc := {
		"on": {"schedule": [{"cron": "0 0 * * *"}]},
		"jobs": {"nightly": {"steps": [{"run": "make"}]}},
	}
	found := violation with input as with_workflow(doc)
	count(found) == 1
	some f in found
	f.verdict == "V-WORKFLOW-NO-CONCURRENCY"
}

# A SCHEDULED WORKFLOW IS NOT ASKED TO CANCEL ITSELF, which is the whole reason
# rules 2 and 3 are separate. `cancel-in-progress: false` is correct there.
test_a_scheduled_workflow_may_decline_to_supersede if {
	doc := {
		"on": {"schedule": [{"cron": "0 0 * * *"}]},
		"concurrency": {"group": "nightly", "cancel-in-progress": false},
		"jobs": {"nightly": {"steps": [{"run": "make"}]}},
	}
	count(violation) == 0 with input as with_workflow(doc)
}

test_a_draft_gated_workflow_missing_ready_for_review_is_refused if {
	doc := object.union(sound.tree.documents[".github/workflows/ci.yml"], {"on": {"pull_request": {"types": ["opened", "synchronize"]}}})
	found := violation with input as with_workflow(doc)
	count(found) == 1
	some f in found
	f.verdict == "V-READY-FOR-REVIEW-UNSUBSCRIBED"
}

# NOT DRAFT-GATED, NOT ASKED. A workflow whose jobs run on a draft has no skipped
# run to supersede, so demanding the subscription would assert more than the
# failure needs.
test_a_workflow_that_does_not_draft_gate_is_not_asked_for_ready if {
	doc := {
		"on": {"pull_request": {"types": ["opened"]}},
		"concurrency": {"group": "ci", "cancel-in-progress": true},
		"jobs": {"build": {"steps": [{"run": "make"}]}},
	}
	found := violation with input as with_workflow(doc)
	every f in found {
		f.verdict != "V-READY-FOR-REVIEW-UNSUBSCRIBED"
	}
}

# THE SCALAR TRIGGER FORM. `on: push` parses to a string, so there is no mapping
# to read and every trigger-keyed predicate stands down rather than erroring.
test_a_scalar_trigger_block_is_not_this_rules_business if {
	doc := {
		"on": "push",
		"concurrency": {"group": "push"},
		"jobs": {"build": {"steps": [{"run": "make"}]}},
	}
	count(violation) == 0 with input as with_workflow(doc)
}

# A `push`-ONLY WORKFLOW IS NOT ASKED FOR A GROUP: its runs are keyed to
# different commits, so they are two subjects rather than two answers to one
# question. Without this the rule refuses an ordinary minimal repository.
test_a_push_only_workflow_is_not_asked_for_a_group if {
	doc := {
		"on": {"push": null},
		"jobs": {"build": {"steps": [{"run": "make"}]}},
	}
	count(violation) == 0 with input as with_workflow(doc)
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT.
test_a_tree_with_no_workflow_is_not_this_rules_business if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

# A DOCUMENT THAT IS NOT A WORKFLOW is not judged: the consumer's glob may select
# a file that parses and carries no jobs.
test_a_document_with_no_jobs_is_not_a_workflow if {
	count(violation) == 0 with input as with_workflow({"name": "notes"})
}
