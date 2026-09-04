# The wiring that decides whether a run happens can be reached at all
# (CLOUD-1161).
#
# The other half of what `ci-local-parity` held. Where `spend-is-authorised`
# asks what a run COSTS, these ask whether the configuration deciding it does
# anything — a trigger no job admits, a filter written where filtering is too
# late, a value truncated before it reaches the forge, two schedules on one
# minute, a fan-in asserting three of its four dependencies. Every one is silent
# when it breaks: the run list looks normal and the conclusion is green.
#
# Names no repository, no directory and no task. The consumer's globs decide
# which files are judged.

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

rules contains "workflow-run-filters-at-the-trigger"

rules contains "comment-trigger-is-anchored"

rules contains "comment-merge-reads-draft-state"

rules contains "declared-trigger-reaches-a-job"

rules contains "schedules-do-not-collide"

rules contains "fan-in-asserts-its-whole-needs"

rules contains "cache-warm-compile-is-guarded"

rules contains "interpolation-is-not-swallowed"

# --- a `workflow_run` trigger filters where filtering is free -----------------
#
# A job `if:` is evaluated AFTER the run already exists, so a branch scope
# expressed only there creates a run and then skips it. Measured on one lane:
# 1131 inserted-and-skipped runs in 25 hours — no runner minutes, which is why it
# survived, but 46% of every run in the repository, enough that paginating the
# run list is no longer stable.
#
# Keyed to the job condition rather than demanded of every `workflow_run`
# trigger: without that, the rule cannot tell a deliberately repository-wide
# trigger from one that meant to be narrow and said so in the wrong place.

job_conditions[path] := conditions if {
	some path, _ in workflow
	conditions := concat("\n", [c |
		some name, job in workflow[path].jobs
		c := condition_text(path, name)
	])
}

condition_text(path, name) := concat("\n", array.concat(
	[object.get(workflow[path].jobs[name], "if", "")],
	[s | some step in workflow[path].jobs[name].steps; s := object.get(step, "if", "")],
))

scopes_head_branch(path) if contains(job_conditions[path], "workflow_run.head_branch")

trigger_filters_branches(path) if _ := triggers(path).workflow_run.branches

violation contains {
	"rule": "workflow-run-filters-at-the-trigger",
	"verdict": "workflow run loose",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	_ := triggers(path).workflow_run
	scopes_head_branch(path)
	not trigger_filters_branches(path)
}

# --- a comment-triggered predicate is anchored --------------------------------
#
# `contains` is an unanchored substring test, so the token fires from
# mid-sentence, from inside backticks, from a quoted block. That makes the
# repository's own writing ABOUT a trigger an invocation of it, and every
# artifact that has to name the token in order to be about it a live round.
#
# Stated over the FIELD rather than as a rule about one token, because the defect
# is the unanchored read of a body anyone can write, not the particular word that
# happened to be read that way.

violation contains {
	"rule": "comment-trigger-is-anchored",
	"verdict": "event bind loose",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	contains(job_conditions[path], "contains(github.event.comment.body")
}

# --- a comment-triggered merge decides the draft question itself --------------
#
# A draft head grades no checks where every pull-request workflow is draft-gated,
# and a branch ruleset admits that empty set as satisfying "required checks
# green". So a merge path that delegates the draft question to the ruleset has no
# draft check at all, and can advance the trunk to a commit CI never ran on.

merges(path) if {
	some _, job in workflow[path].jobs
	some step in job.steps
	object.get(step, "with", {}).merge == true
}

reads_draft_state(path) if contains(job_conditions[path], ".draft")

reads_draft_state(path) if {
	some _, job in workflow[path].jobs
	some step in job.steps
	contains(object.get(step, "run", ""), ".draft")
}

violation contains {
	"rule": "comment-merge-reads-draft-state",
	"verdict": "merge run early",
	"subjects": [{"path": path}],
} if {
	some path, _ in workflow
	_ := triggers(path).issue_comment
	merges(path)
	not reads_draft_state(path)
}

# --- a declared trigger can reach a job ---------------------------------------
#
# A trigger the workflow declares and no job condition admits produces a run that
# starts and then skips every job: the trigger exists and does nothing, and only
# the job's conclusion says so.
#
# THE PREDICATE IS NARROW ON PURPOSE, because a condition is an expression
# language and this is a structural rule. It fires only where the answer is
# unambiguous: a workflow whose conditions MENTION the event name at all is
# claiming to discriminate by event, so every trigger it declares must be named
# in some condition. A workflow with no such mention admits everything and
# answers for every trigger, so it is not judged.

discriminates_by_event(path) if contains(job_conditions[path], "github.event_name")

admits(path, trigger) if contains(job_conditions[path], sprintf("github.event_name == '%s'", [trigger]))

admits(path, trigger) if contains(job_conditions[path], sprintf("github.event_name == \"%s\"", [trigger]))

# `workflow_run` is admitted by READING ITS PAYLOAD, which is only populated
# under that event and is therefore as strong a claim as naming it.
admits(path, "workflow_run") if contains(job_conditions[path], "github.event.workflow_run")

violation contains {
	"rule": "declared-trigger-reaches-a-job",
	"verdict": "event reach dead",
	"subjects": [{"path": path}, {"artifact": trigger}],
} if {
	some path, _ in workflow
	discriminates_by_event(path)
	some trigger, _ in triggers(path)
	not admits(path, trigger)
}

# --- no two schedules collide -------------------------------------------------
#
# Compared as LITERAL cron expressions, never as firing times. An
# every-30-minutes schedule genuinely overlaps every hourly slot, and flagging
# that would make the rule fire forever on a workflow doing nothing wrong.
# Literal equality is also what "a staggered slot" means in the headers that
# claim one.

cron_of contains [path, expr] if {
	some path, _ in workflow
	some entry in triggers(path).schedule
	expr := entry.cron
}

colliding contains expr if {
	some [_, expr] in cron_of
	count({p | some [p, e] in cron_of; e == expr}) > 1
}

violation contains {
	"rule": "schedules-do-not-collide",
	"verdict": "job start same",
	"subjects": [{"path": path}, {"artifact": expr}],
} if {
	some expr in colliding
	some [path, e] in cron_of
	e == expr
}

# --- a fan-in asserts its whole `needs:` set ----------------------------------
#
# Branch protection points at one aggregating job so that adding a leg never
# needs a ruleset change — which only holds if that job's assertion follows
# `needs:` by itself. Measured: a fan-in enumerated three of its four
# dependencies, so a red fourth left green the one check the host requires.
#
# Satisfied EITHER by a set-wide predicate, which cannot go stale because it
# names nothing, OR by naming every dependency. Both spellings of a name count,
# since a key with a hyphen is legal written either way.

job_body(path, name) := concat("\n", array.concat(
	[condition_text(path, name)],
	[r | some step in workflow[path].jobs[name].steps; r := object.get(step, "run", "")],
))

asserts_the_whole_set(path, name) if contains(job_body(path, name), "needs.*")

names_the_dependency(path, name, dep) if contains(job_body(path, name), sprintf("needs.%s", [dep]))

names_the_dependency(path, name, dep) if contains(job_body(path, name), sprintf("needs['%s']", [dep]))

violation contains {
	"rule": "fan-in-asserts-its-whole-needs",
	"verdict": "job require unseen",
	"subjects": [{"path": path}, {"artifact": dep}],
} if {
	some path, _ in workflow
	some name, job in workflow[path].jobs
	count(job_body(path, name)) > 0
	some dep in job.needs
	not asserts_the_whole_set(path, name)
	some_dependency_is_named(path, name)
	not names_the_dependency(path, name, dep)
}

# THE SCOPE, and it is what keeps this from firing on every ordinary job. A job
# that names NO dependency is not making a claim about its `needs:` at all — it
# simply waits, which is what `needs:` is for. The defect is a job that asserts
# SOME of its dependencies and thereby looks like it asserts them all.
some_dependency_is_named(path, name) if {
	some dep in workflow[path].jobs[name].needs
	names_the_dependency(path, name, dep)
}

# --- a cache-warm compile is guarded ------------------------------------------
#
# A build that compiles to fill a cache and runs nothing judges nothing, which is
# why it is exempt elsewhere — and that exemption is also what makes it easy to
# leave running for nothing. Measured: two cache entries carrying the SAME key
# across five merges, each cycle compiling for ~145s and writing nothing, because
# the restore skips saving when the key already exists.
#
# The rule names BOTH halves, because of the direction it can rot in. If the
# action stops emitting the hit flag, the expression is empty, the guard holds
# and the compile runs — wasteful, but visible in the bill. If the step id is
# dropped or renamed while the guard keeps naming it, the expression is ALSO
# empty and the job silently reverts to compiling every time. Same symptom, no
# signal.

warm_step(path, name, index) if {
	step := workflow[path].jobs[name].steps[index]
	contains(object.get(step, "run", ""), "--no-run")
}

guarded_on_cache_hit(path, name, index) if {
	contains(workflow[path].jobs[name].steps[index]["if"], "cache-hit")
}

# A CACHE MUST BE PRESENT BEFORE A CACHE GUARD CAN BE DEMANDED.
#
# `warm_step` reads `--no-run` as its proxy for "a compile that fills a cache",
# and that proxy is one-sided: `--no-run` says the step compiles and runs
# nothing, never that a cache is involved. A job that compiles to MEASURE — a
# runner benchmark, a build-throughput probe — matches identically and has no
# cache at all, so the demanded guard is unsatisfiable rather than merely
# missing: `steps.<id>.outputs.cache-hit` resolves to empty with no cache action
# in the job, the guard then admits everything, and naming an id no step carries
# is this rule's OTHER arm. Both routes out are worse than the finding.
#
# The measured harm this rule exists for needs the cache to exist — "two cache
# entries carrying the SAME key across five merges... the restore skips saving
# when the key already exists" is a statement about a restore. With no restore
# there is nothing to skip and nothing wasted beyond the compile somebody asked
# for on purpose.
#
# THE DIRECTION OF THE MISS, stated because it is real: keyed on `uses`
# containing `cache`, which is the ecosystem's own spelling and names no
# consumer. A caching action whose name omits it would now go unjudged — but
# such a job could not express the guard either, since the guard references a
# `cache-hit` output only a cache action emits, so the rule was unenforceable
# there before this conjunct rather than after it.
job_caches(path, name) if {
	some step in workflow[path].jobs[name].steps
	contains(object.get(step, "uses", ""), "cache")
}

violation contains {
	"rule": "cache-warm-compile-is-guarded",
	"verdict": "cache build loose",
	"subjects": [{"path": path}, {"artifact": name}],
} if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	some index, _ in workflow[path].jobs[name].steps
	warm_step(path, name, index)
	job_caches(path, name)
	not guarded_on_cache_hit(path, name, index)
}

# The guard names a step; that step must exist, or the expression resolves to
# empty and the guard silently admits everything.
#
# INLINE, and that is the preset shape rather than the exemption taken as
# licence. `policy.rs`'s `[[pattern]]` check exempts a preset because the demand
# is unsatisfiable, in its own words: "A preset is compiled in; a consumer cannot
# add a `[[pattern]]` row on its behalf, and the preset cannot read one." A
# consumer row is therefore not a stricter option here, it is a DEAD one — this
# read resolved to undefined for every consumer, so the body never held and the
# rule gated nothing. Rule 1 still binds the literal, and it holds: the shape is
# GitHub Actions' own, naming no consumer.
cache_hit_step_id := `steps\.[A-Za-z0-9_-]+\.outputs\.cache-hit`

guard_names(path, name, index) := id if {
	guard := workflow[path].jobs[name].steps[index]["if"]
	found := regex.find_n(cache_hit_step_id, guard, 1)
	id := split(split(found[0], ".")[1], ".")[0]
}

step_id_exists(path, id) if {
	some _, job in workflow[path].jobs
	some step in job.steps
	step.id == id
}

violation contains {
	"rule": "cache-warm-compile-is-guarded",
	"verdict": "cache name unknown",
	"subjects": [{"path": path}, {"artifact": id}],
} if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	some index, _ in workflow[path].jobs[name].steps
	warm_step(path, name, index)
	id := guard_names(path, name, index)
	not step_id_exists(path, id)
}

# --- a value's interpolation is not swallowed by a comment --------------------
#
# YAML opens a comment at an unquoted ` #`, so a line like
# `run-name: land #${{ github.event.issue.number }}` parses to the bare string
# `land` and the interpolation is discarded. Measured: one workflow carried
# exactly that for a day, and 30 consecutive runs reported a display title equal
# to the workflow NAME, so a lander keying on the interpolated value could never
# match — restoring a "cannot see a refusal, so it polls forever" stall while the
# success path masked it. Linters pass over the line, because a comment is legal
# YAML, and review reads it as the thing it was meant to be.
#
# READ FROM `lines`, NOT THE DOCUMENT, and that is forced rather than chosen: the
# parse is what DESTROYS the evidence. By the time the value is a node it is
# already truncated, and nothing downstream can tell a deliberately short string
# from a swallowed one.
#
# ANCHORED, NEVER COUNTED, and the difference is measured. The obvious predicate
# — compare the raw `${{` count against the count surviving a parse — flags 4 of
# one repository's 20 workflows and 3 are prose comments legitimately discussing
# interpolation. A gate that is 75% false positives gets switched off, which is
# worse than no gate. Requiring a `key:` before the `#` and an interpolation
# after it, with whole-line comments excluded, flags the real defect and nothing
# else.
#
# The first value character must not be a quote: a quoted scalar carries its `#`
# as data, and that is the REPAIR this rule asks for, so matching it would make
# the rule refuse its own remedy.

# Inline for the reason `cache_hit_step_id` above states: a preset cannot read a
# consumer's `[[pattern]]` row, so spelling these as registry lookups made both
# reads undefined and this predicate unreachable. Neither literal names a
# consumer — one is YAML's comment syntax, the other its interpolation syntax.
swallowed_interpolation := `^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*[^"'#[:space:]][^#]*[[:space:]]#.*\$\{\{`

whole_line_comment := `^[[:space:]]*#`

swallowed(line) if {
	regex.match(swallowed_interpolation, line)
	not regex.match(whole_line_comment, line)
}

violation contains {
	"rule": "interpolation-is-not-swallowed",
	"verdict": "input render dropped",
	"subjects": [{"path": path, "line": number}],
} if {
	some path, lines in input.tree.lines
	some index, line in lines
	swallowed(line)
	number := index + 1
}

# --- cases --------------------------------------------------------------------

wf(doc) := {"tree": {"documents": {".github/workflows/a.yml": doc}}}

test_a_workflow_run_scoped_only_in_a_job_condition_is_refused if {
	doc := {
		"on": {"workflow_run": {"workflows": ["ci"]}},
		"concurrency": {"group": "g"},
		"jobs": {"land": {
			"if": "startsWith(github.event.workflow_run.head_branch, 'bot/')",
			"steps": [{"run": "land"}],
		}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "workflow run loose"
}

test_a_trigger_level_branches_filter_satisfies_it if {
	doc := {
		"on": {"workflow_run": {"workflows": ["ci"], "branches": ["bot/**"]}},
		"concurrency": {"group": "g"},
		"jobs": {"land": {
			"if": "startsWith(github.event.workflow_run.head_branch, 'bot/')",
			"steps": [{"run": "land"}],
		}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "workflow run loose"
	}
}

# A workflow with no branch condition at all is not asked for a filter: a
# deliberately repository-wide trigger is not a defect.
test_a_workflow_run_with_no_branch_condition_is_not_asked if {
	doc := {
		"on": {"workflow_run": {"workflows": ["ci"]}},
		"concurrency": {"group": "g"},
		"jobs": {"land": {"steps": [{"run": "land"}]}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "workflow run loose"
	}
}

test_an_unanchored_comment_predicate_is_refused if {
	doc := {
		"on": {"issue_comment": {"types": ["created"]}},
		"concurrency": {"group": "g"},
		"jobs": {"go": {"if": "contains(github.event.comment.body, '/land')", "steps": [{"run": "go"}]}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "event bind loose"
}

test_an_anchored_comment_predicate_passes if {
	doc := {
		"on": {"issue_comment": {"types": ["created"]}},
		"concurrency": {"group": "g"},
		"jobs": {"go": {"if": "startsWith(github.event.comment.body, '/land')", "steps": [{"run": "go"}]}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "event bind loose"
	}
}

test_a_comment_merge_that_ignores_draft_state_is_refused if {
	doc := {
		"on": {"issue_comment": {"types": ["created"]}},
		"concurrency": {"group": "g"},
		"jobs": {"go": {
			"if": "startsWith(github.event.comment.body, '/land')",
			"steps": [{"uses": "some/merge", "with": {"merge": true}}],
		}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "merge run early"
}

# A comment-triggered workflow that does NOT merge is not asked the draft
# question: the defect is advancing the trunk, not reading a comment.
test_a_comment_workflow_that_does_not_merge_is_not_asked if {
	doc := {
		"on": {"issue_comment": {"types": ["created"]}},
		"concurrency": {"group": "g"},
		"jobs": {"go": {
			"if": "startsWith(github.event.comment.body, '/note')",
			"steps": [{"run": "echo hi"}],
		}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "merge run early"
	}
}

test_a_trigger_no_condition_admits_is_refused_and_named if {
	doc := {
		"on": {"schedule": [{"cron": "0 1 * * *"}], "workflow_dispatch": null},
		"concurrency": {"group": "g"},
		"jobs": {"go": {"if": "github.event_name == 'schedule'", "steps": [{"run": "go"}]}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "event reach dead"
	some s in f.subjects
	s.artifact == "workflow_dispatch"
}

test_a_workflow_admitting_both_triggers_passes if {
	doc := {
		"on": {"schedule": [{"cron": "0 1 * * *"}], "workflow_dispatch": null},
		"concurrency": {"group": "g"},
		"jobs": {"go": {
			"if": "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
			"steps": [{"run": "go"}],
		}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "event reach dead"
	}
}

# A CONDITION THAT MENTIONS NO EVENT ADMITS EVERYTHING, so a workflow carrying
# one is not judged. Without this the rule would fire on every ordinary workflow.
test_a_condition_mentioning_no_event_is_not_judged if {
	doc := {
		"on": {"schedule": [{"cron": "0 1 * * *"}], "workflow_dispatch": null},
		"concurrency": {"group": "g"},
		"jobs": {"go": {"if": "always()", "steps": [{"run": "go"}]}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "event reach dead"
	}
}

test_two_workflows_sharing_a_cron_are_refused if {
	docs := {
		".github/workflows/a.yml": {
			"on": {"schedule": [{"cron": "0 3 * * *"}]},
			"concurrency": {"group": "a"},
			"jobs": {"a": {"steps": [{"run": "a"}]}},
		},
		".github/workflows/b.yml": {
			"on": {"schedule": [{"cron": "0 3 * * *"}]},
			"concurrency": {"group": "b"},
			"jobs": {"b": {"steps": [{"run": "b"}]}},
		},
	}
	found := violation with input as {"tree": {"documents": docs}}
	count({p |
		some f in found
		f.verdict == "job start same"
		some s in f.subjects
		p := s.path
	}) == 2
}

test_a_staggered_pair_passes if {
	docs := {
		".github/workflows/a.yml": {
			"on": {"schedule": [{"cron": "0 3 * * *"}]},
			"concurrency": {"group": "a"},
			"jobs": {"a": {"steps": [{"run": "a"}]}},
		},
		".github/workflows/b.yml": {
			"on": {"schedule": [{"cron": "30 3 * * *"}]},
			"concurrency": {"group": "b"},
			"jobs": {"b": {"steps": [{"run": "b"}]}},
		},
	}
	found := violation with input as {"tree": {"documents": docs}}
	every f in found {
		f.verdict != "job start same"
	}
}

# LITERAL EQUALITY, NEVER FIRING-TIME OVERLAP: an every-30-minutes schedule
# genuinely overlaps every hourly slot, and flagging that would make the rule
# fire forever on a workflow doing nothing wrong.
test_an_overlapping_but_distinct_expression_is_not_a_collision if {
	docs := {
		".github/workflows/a.yml": {
			"on": {"schedule": [{"cron": "*/30 * * * *"}]},
			"concurrency": {"group": "a"},
			"jobs": {"a": {"steps": [{"run": "a"}]}},
		},
		".github/workflows/b.yml": {
			"on": {"schedule": [{"cron": "0 3 * * 1"}]},
			"concurrency": {"group": "b"},
			"jobs": {"b": {"steps": [{"run": "b"}]}},
		},
	}
	found := violation with input as {"tree": {"documents": docs}}
	every f in found {
		f.verdict != "job start same"
	}
}

test_a_fan_in_that_enumerates_only_some_of_its_needs_is_refused if {
	doc := {
		"on": {"pull_request": {"types": ["opened"]}},
		"concurrency": {"group": "g", "cancel-in-progress": true},
		"jobs": {"final": {
			"needs": ["a", "b"],
			"if": "always()",
			"steps": [{"run": "test needs.a.result = success"}],
		}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "job require unseen"
	some s in f.subjects
	s.artifact == "b"
}

# THE SET-WIDE SPELLING CANNOT GO STALE, because it names nothing.
test_a_fan_in_asserting_over_the_whole_set_passes if {
	doc := {
		"on": {"pull_request": {"types": ["opened"]}},
		"concurrency": {"group": "g", "cancel-in-progress": true},
		"jobs": {"final": {
			"needs": ["a", "b"],
			"if": "always()",
			"steps": [{"run": "echo needs.* | check"}],
		}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "job require unseen"
	}
}

# AN ORDINARY JOB THAT SIMPLY WAITS IS NOT MAKING A CLAIM. Without this scope the
# rule would fire on every job carrying a `needs:`, which is what `needs:` is for.
test_a_job_that_names_no_dependency_is_not_judged if {
	doc := {
		"on": {"pull_request": {"types": ["opened"]}},
		"concurrency": {"group": "g", "cancel-in-progress": true},
		"jobs": {"deploy": {"needs": ["a", "b"], "steps": [{"run": "deploy"}]}},
	}
	found := violation with input as wf(doc)
	every f in found {
		f.verdict != "job require unseen"
	}
}

test_an_unguarded_cache_warm_compile_is_refused if {
	doc := {
		"on": {"push": null},
		"concurrency": {"group": "g"},
		"jobs": {"warm": {"steps": [
			{"uses": "cache/restore", "id": "cache"},
			{"run": "cargo test --no-run"},
		]}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "cache build loose"
}

test_a_guarded_cache_warm_compile_passes if {
	doc := {
		"on": {"push": null},
		"concurrency": {"group": "g"},
		"jobs": {"warm": {"steps": [
			{"uses": "cache/restore", "id": "cache"},
			{"run": "cargo test --no-run", "if": "steps.cache.outputs.cache-hit != 'true'"},
		]}},
	}
	found := violation with input as wf(doc)
	count(found) == 0
}

# THE OTHER DIRECTION, and it has the same symptom as the first: a guard naming a
# step id nothing declares resolves to empty and admits every run.
test_a_guard_naming_a_missing_step_id_is_refused if {
	doc := {
		"on": {"push": null},
		"concurrency": {"group": "g"},
		"jobs": {"warm": {"steps": [
			{"uses": "cache/restore", "id": "restore"},
			{"run": "cargo test --no-run", "if": "steps.cache.outputs.cache-hit != 'true'"},
		]}},
	}
	found := violation with input as wf(doc)
	some f in found
	f.verdict == "cache name unknown"
	some s in f.subjects
	s.artifact == "cache"
}

# A TREE WITH NO SUCH JOB IS SILENT BY DESIGN here, unlike the properties whose
# subject set must be non-empty: a repository with no cache-warm build has
# nothing to guard, which is a legitimate shape rather than a look that failed.
test_a_tree_with_no_warm_compile_is_silent if {
	doc := {
		"on": {"push": null},
		"concurrency": {"group": "g"},
		"jobs": {"build": {"steps": [{"run": "cargo test"}]}},
	}
	count(violation) == 0 with input as wf(doc)
}

test_an_unquoted_hash_that_swallows_an_interpolation_is_refused if {
	found := violation with input as {"tree": {"documents": {}, "lines": {".github/workflows/a.yml": [
		"name: Land",
		"run-name: land #${{ github.event.issue.number }}",
	]}}}
	count(found) == 1
	some f in found
	f.verdict == "input render dropped"
	some s in f.subjects
	s.line == 2
}

# THE REPAIR MUST NOT BE REFUSED. A quoted scalar carries its `#` as data, and
# quoting is exactly what this rule asks for — a gate that refuses its own remedy
# is one nobody can satisfy. Found by the shell original refusing its own fix on
# its first run, which is the cheapest way to find it.
test_the_same_value_quoted_passes if {
	found := violation with input as {"tree": {"documents": {}, "lines": {".github/workflows/a.yml": ["run-name: \"land #${{ github.event.issue.number }}\""]}}}
	count(found) == 0
}

# A WHOLE-LINE COMMENT IS PROSE. These files discuss interpolation at length, and
# a rule that fired on its own documentation is one people delete.
test_a_whole_line_comment_mentioning_an_interpolation_passes if {
	found := violation with input as {"tree": {"documents": {}, "lines": {".github/workflows/a.yml": ["  # the value is ${{ github.event.issue.number }} here"]}}}
	count(found) == 0
}

# A TRAILING COMMENT WITH NO INTERPOLATION AFTER IT swallows nothing.
test_a_trailing_comment_with_no_interpolation_passes if {
	found := violation with input as {"tree": {"documents": {}, "lines": {".github/workflows/a.yml": ["runs-on: ubuntu-latest # the cheap runner"]}}}
	count(found) == 0
}
