# METADATA
# description: |
#   A gate must not share a trigger with the failure it watches (CLOUD-1777).
#
#   `release-assets.yml` answers "does the latest release actually carry its
#   binaries?". CLOUD-258 moved it off the `release` event on exactly this
#   reasoning — a `release`-triggered run reaches no PR and no gate, so a
#   workflow failing on 100% of its invocations was indistinguishable from one
#   that had never fired — and then put it on a clock slower than the thing it
#   samples, which reintroduces the same blindness as latency instead of as
#   silence. Measured: a weekly cron against ~4 releases/day inspects roughly
#   one release in thirty, and v0.0.159 shipped 1 asset of 18 with nothing due
#   to say so for four days. v0.0.160 then did it again the next day.
#
#   WHAT MAKES A TRIGGER INDEPENDENT HERE. The failure is that a release created
#   with `GITHUB_TOKEN` does not fire workflows — GitHub's recursion guard. So
#   `release` is disqualified by construction: it is the event the guard
#   swallows. `schedule` and `workflow_dispatch` are not per-release at all — a
#   clock samples whatever is latest when it happens to run, and a dispatch is a
#   human. What is left, and what this asserts, is a trigger that fires once per
#   release from a channel the guard does not reach: a `push` to the trunk, or a
#   `workflow_run` on the workflow that does the releasing, since release-plz is
#   itself `on: push`.
#
#   THE ARM DENIES ON ABSENCE, WHICH IS THE WHOLE POINT OF WRITING IT AS A
#   MODULE. An earlier revision of CLOUD-1777 concluded this had no rule shape —
#   "no rule form asserts a pattern must be PRESENT, `[[pattern]]` rows refuse on
#   match" — and deferred the guard to a bats suite that `shell edit refused`
#   then refused. That reasoning was wrong: a rego module is deny-only, so
#   presence is asserted by denying on absence, with a `not` in the rule body.
#   `[[pattern]]` is a named-regex registry rather than a rule type, and reading
#   it as the only pattern-shaped form is what produced the wrong conclusion.
#
#   THE SUBJECT IS FOUND BY WHAT IT RUNS, NOT BY ITS PATH. The workflow is
#   whichever one invokes the release-asset check, so the arm follows the gate if
#   the file is renamed or the step moves — a path literal would go silently
#   vacuous on exactly that move, which is the dead-gate class this repository
#   keeps re-meeting.
#
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_trigger_independent

import rego.v1

rules contains "release watch late"

# Every parsed workflow, by path.
#
# ABSENT IS NOT EMPTY. A tree carrying no parsed workflow leaves this empty,
# `governed` false, and the arm silent — a module that reported a clean tree it
# never read is the vacuous pass this repository prices everywhere else.
workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

# The workflow under test: the one whose steps run the release-asset check.
watcher contains path if {
	some path, doc in workflow
	some _, job in doc.jobs
	some step in job.steps
	contains(step.run, "release-assets-check")
}

governed if count(watcher) > 0

triggers(path) := t if {
	t := workflow[path].on
	is_object(t)
}

# A trigger that fires once per release AND is not the event the recursion guard
# swallows. `push` is the trunk write that publishes; `workflow_run` is the
# release workflow's own completion, which is itself reached by a push.
independent(path) if _ := triggers(path).push

independent(path) if _ := triggers(path).workflow_run

# The gate watches releases on a trigger the failure can silence, or on no
# per-release trigger at all.
#
# POINTER-ONLY: the workflow's path. Never the trigger block — a finding that
# printed it would be restating the config it refuses.
violation contains {
	"rule": "release watch late",
	"verdict": "release watch late",
	"subjects": [{"path": path}],
} if {
	governed
	some path in watcher
	not independent(path)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.documents` for a workflow path, or that it parses `on:` as the
# string key rather than YAML 1.1's boolean `true` — a `with input as` case
# fabricates the very shape the engine may be unable to produce. `batten-check`
# over this repository's own committed workflow is what answers that, and it is
# why the arm is enabled on this tree rather than only tested here.

wf(on) := {"tree": {"documents": {".github/workflows/release-assets.yml": {
	"on": on,
	"jobs": {"release-assets": {"steps": [{"run": "mise run release-assets-check \"$TAG\""}]}},
}}}}

test_the_committed_shape_is_clean if {
	count(violation) == 0 with input as wf({"workflow_run": {"workflows": ["release-plz"]}, "schedule": [{"cron": "30 6 * * 1"}]})
}

# A push to the trunk is the other independent shape, and it passes for the same
# reason: the recursion guard does not reach it.
test_a_push_trigger_is_independent if {
	count(violation) == 0 with input as wf({"push": {"branches": ["main"]}})
}

# THE CASE THE ROW EXISTS FOR — the shape that shipped v0.0.159 assetless.
test_a_clock_alone_is_refused if {
	some v in violation with input as wf({"schedule": [{"cron": "30 6 * * 1"}], "workflow_dispatch": {}})
	v.verdict == "release watch late"
}

# And the other half of CLOUD-258's finding: the event the guard swallows is not
# a per-release trigger for this purpose, however per-release it looks.
test_the_release_event_alone_is_refused if {
	some v in violation with input as wf({"release": {"types": ["published"]}})
	v.verdict == "release watch late"
}

# ANTI-VACUITY. Without this the arm is satisfied by a predicate that fires on
# every workflow, which would refuse the whole tree rather than this one gate.
test_a_workflow_that_does_not_watch_releases_is_untouched if {
	count(violation) == 0 with input as {"tree": {"documents": {".github/workflows/ci.yml": {
		"on": {"schedule": [{"cron": "0 5 * * *"}]},
		"jobs": {"ci": {"steps": [{"run": "mise run ci"}]}},
	}}}}
}

# COULD NOT LOOK IS NOT A PASS. A tree with no parsed workflow answers nothing.
test_no_workflow_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

#MUTANT release-trigger-absence-admitted|s@	not independent(path)@	false@|a_clock_alone_is_refused
