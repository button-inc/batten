# CI confirms what `verify` proved, over THIS repository's own wiring
# (CLOUD-1161).
#
# The consumer half of `ci-local-parity`'s retirement. The generic half — what a
# run costs, and whether a declared trigger can reach a job — ships as the
# `ci-hygiene` preset, because it is true of the practice. Everything here names
# something only this repository has: a required-check roster, a task called
# `verify`, a fan-in called `final`, the branch prefixes two bots land on, the
# ecosystems this tree maintains. Non-negotiable rule 1 is what keeps them out of
# the core, and the split is the whole reason there are two files.
#
# WHAT THE RETIRED PROGRAM'S HEADER NUMBERED, and what it did not. That header
# numbers seventeen properties; the body reuses four of those numbers for
# DIFFERENT predicates and carries two the header never lists. Reading the body's
# labels as the header's is how a port silently drops a property, so this module
# is organised by what each clause decides and cites the header's number only
# where the two agree.
#
# THE ONE PREDICATE THAT DID NOT COME HERE, stated rather than left to be
# noticed. The foreign-runner second-spelling check read `mise tasks info
# test:cargo --json` — mise's own answer about its own task graph. A policy
# module cannot spawn, and the only substitute available here is re-parsing
# `mise.toml`, which is exactly the second authority the retired program refused
# at its own `:881-885`: "a second parser is a second authority on a body mise
# already owns." So that predicate stays a mise task
# (`[tasks."cargo-spelling"]`), where mise answers for itself, rather than being
# re-derived in Rego. It is the one clause of the retired program that is not in
# this file, and it is absent on purpose.
#
#MUTANT roster-may-miss-a-job|s@not job_in_roster(name)@false@|a pull_request job missing from CI_REQUIRED_CHECKS is refused
#MUTANT roster-may-name-a-ghost|s@not roster_name_has_a_job(name)@false@|a required name matching no job is refused
#MUTANT dependabot-may-return|s@not dependabot_absent@false@|a dependabot config that comes back is refused
#MUTANT lander-may-not-abandon|s@not lander_calls_abandon@false@|a lander that never calls abandon-matrix is refused
#
#MUTANT-EXEMPT CLOUD-1161|no `tests/ci-parity.bats` exists and none may: this row is a retirement under CLOUD-843, whose whole subject is that the predicate stops living in a bats suite, and `V-SHELL-RULE-ADDED` refuses adding one at deny. `mutant` resolves a gate's suite as `tests/$gate.bats`, so there is no named case a mutation could turn red; the second tier is `crates/batten/tests/ci_parity.rs`, which drives the compiled binary over real workflow fixtures

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_parity

import rego.v1

rules contains "ci-task-parity"

rules contains "required-roster-matches-jobs"

rules contains "release-pr-opens-as-a-draft"

rules contains "one-bot-serves-every-ecosystem"

rules contains "fan-in-is-wired"

rules contains "lease-authorises-before-spending"

rules contains "check-status-decided-in-one-place"

rules contains "every-bot-branch-has-a-watcher"

# --- the manifest, and the guard ----------------------------------------------

manifest := input.tree.documents["mise.toml"]

# A repository with no `verify` task is answering for nothing here. The guard
# matters for `hk-fix-selection`'s measured reason: an unguarded module reported
# seven findings against a fixture carrying a copy of the config and none of its
# subjects.
governed if manifest.tasks.verify

# WHAT `mise run verify` ACTUALLY RUNS, and it is TWO blocks rather than one.
# `verify` is a dependency-free exit-code mapper since CLOUD-407 and the gate set
# moved to `verify:gated`; a reader that follows only the first hop reports every
# one of those tasks as CI-only. That is a false alarm rather than a missed one,
# but it fires on every commit, which is its own defect.
#
# The hop is spelled out rather than chased generically, for the retired
# program's stated reason: `verify` names its successor in exactly one place, a
# third link would break this loudly, and an evaluator that followed `mise run`
# calls transitively would be a second authority on the task graph mise owns.
verify_text := concat("\n", [
	object.get(manifest.tasks, ["verify", "run"], ""),
	concat(" ", object.get(manifest.tasks, ["verify", "depends"], [])),
	object.get(manifest.tasks, ["verify:gated", "run"], ""),
	concat(" ", object.get(manifest.tasks, ["verify:gated", "depends"], [])),
])

# --- the workflows ------------------------------------------------------------

workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

triggers(path) := t if {
	t := workflow[path].on
	is_object(t)
}

on_pull_request(path) if _ := triggers(path).pull_request

# A check-run's name is the job's `name:`; a matrix leg gets the leg appended in
# parentheses, which no committed text can expand. Comparison is therefore over
# the BASE name — enough to catch a job added, removed or renamed, which is what
# rots a hand-maintained list.
base_name(name) := trim_space(split(name, "(")[0])

# --- every task CI runs is one `verify` runs (header property 3) --------------
#
# AND ONLY FROM A JOB THIS MACHINE COULD HAVE RUN. The property's premise is that
# a free local run would have caught it, and that is false for a job on an OS the
# author is not — there is no local Windows — so applied there it is not a parity
# check but a prohibition on cross-OS jobs.
#
# The exemption is an ALLOWLIST OF FOREIGN LABELS rather than of Linux ones, and
# the direction is the whole correctness of it: exempting anything that is not
# `ubuntu-*` would also exempt `self-hosted`, a matrix expression, and any label
# nobody has classified — switching the property off for jobs it should judge.

foreign_runner(runner) if startswith(runner, "windows-")

foreign_runner(runner) if startswith(runner, "macos-")

judged_job(path, name) if {
	on_pull_request(path)
	not foreign_runner(object.get(workflow[path].jobs[name], "runs-on", ""))
}

# The `run:` scalars, never the prose. These files carry long comments that name
# tasks in order to explain why they are ABSENT, and a gate that fires on its own
# documentation is a gate people delete.
# A PARTIAL SET RATHER THAN A FUNCTION, and the difference is not style: a job
# runs many tasks, and a Rego function that bound more than one output faults at
# evaluation rather than returning them. The pair carries the workflow so the
# finding can point at it.
ci_task_used contains [path, task] if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	judged_job(path, name)
	some step in workflow[path].jobs[name].steps
	some fragment in regex.find_n(data.batten.patterns["mise-run-task"], step.run, -1)
	task := split(fragment, " ")[2]
}

violation contains {
	"rule": "ci-task-parity",
	"verdict": "V-CI-TASK-NOT-IN-VERIFY",
	"subjects": [{"path": path}, {"artifact": task}],
} if {
	governed
	some [path, task] in ci_task_used
	not contains(verify_text, task)
}

# --- the required roster names exactly the pull-request jobs (property 5) -----
#
# Both directions, and each is a different false green. A job added and not
# listed is silently unrequired, which is the shape CLOUD-327 records; a listed
# name matching no job waits forever for a run nothing will ever create.

roster_names contains base_name(trim_space(part)) if {
	some part in split(manifest.env.CI_REQUIRED_CHECKS, ",")
	trim_space(part) != ""
}

job_display_names contains base_name(name) if {
	some path, _ in workflow
	on_pull_request(path)
	some key, job in workflow[path].jobs
	name := object.get(job, "name", key)
}

job_in_roster(name) if name in roster_names

roster_name_has_a_job(name) if name in job_display_names

violation contains {
	"rule": "required-roster-matches-jobs",
	"verdict": "V-REQUIRED-CHECK-NAMES-NO-JOB",
	"subjects": [{"path": "mise.toml"}, {"artifact": name}],
} if {
	governed
	some name in roster_names
	not roster_name_has_a_job(name)
}

violation contains {
	"rule": "required-roster-matches-jobs",
	"verdict": "V-JOB-NOT-IN-REQUIRED-ROSTER",
	"subjects": [{"path": "mise.toml"}, {"artifact": name}],
} if {
	governed
	some name in job_display_names
	not job_in_roster(name)
}

# --- the release PR opens as a draft (property 4) -----------------------------
#
# release-plz rewrites its branch on every push to the trunk, and a non-draft
# pull request turns each of those refreshes into a full matrix on a diff that is
# a version bump and a changelog entry — measured at 5 of 30 runs in one
# 37-minute window, four of them thrown away by the next refresh. `pr_draft` is
# the whole mechanism, so it is the thing to sense.

release_config := input.tree.documents["release-plz.toml"]

violation contains {
	"rule": "release-pr-opens-as-a-draft",
	"verdict": "V-RELEASE-PR-NOT-DRAFT",
	"subjects": [{"path": "release-plz.toml"}],
} if {
	governed
	release_config
	object.get(release_config, ["pr", "pr_draft"], false) != true
	object.get(release_config, ["pr_draft"], false) != true
}

# --- one bot serves every ecosystem this tree maintains (properties 12-14) ----

renovate := input.tree.documents["renovate.json5"]

# 12, INVERTED. The file is gone and must stay gone; a re-added `dependabot.yml`
# puts a second bot back on ecosystems the first already owns, and nothing else
# in this tree would go red about it. Read from `tracked` because the predicate
# is about a path EXISTING, which a parsed document cannot answer — an absent
# document and an unparseable one look the same there.
dependabot_absent if not ".github/dependabot.yml" in input.tree.tracked

violation contains {
	"rule": "one-bot-serves-every-ecosystem",
	"verdict": "V-DEPENDABOT-RETURNED",
	"subjects": [{"path": ".github/dependabot.yml"}],
} if {
	governed
	not dependabot_absent
}

# 13. THE FIVE KEYS THAT DECIDE WHAT THE LANE SPENDS AND WHAT IT COVERS. Each is
# matched with its VALUE, because a key set to anything but the fix is the same
# defect as the key absent. `prConcurrentLimit` is where that bites hardest:
# Renovate reads `0` as UNLIMITED, so the bound and its own negation differ by a
# single character.
renovate_key_ok("draftPR") if renovate.draftPR == true

renovate_key_ok("rebaseWhen") if renovate.rebaseWhen == "behind-base-branch"

renovate_key_ok("prConcurrentLimit") if renovate.prConcurrentLimit > 0

renovate_key_ok("minimumReleaseAge") if count(renovate.minimumReleaseAge) > 0

renovate_key_ok("vulnerabilityAlerts") if is_object(renovate.vulnerabilityAlerts)

violation contains {
	"rule": "one-bot-serves-every-ecosystem",
	"verdict": "V-RENOVATE-BOUND-MISSING",
	"subjects": [{"path": "renovate.json5"}, {"artifact": key}],
} if {
	governed
	renovate
	some key in ["draftPR", "rebaseWhen", "prConcurrentLimit", "minimumReleaseAge", "vulnerabilityAlerts"]
	not renovate_key_ok(key)
}

# THE FIFTH KEY, ASSERTED WHERE IT MUST BE WRITTEN rather than merely present.
# A top-level `semanticCommitType` is exactly where it DOES NOT WORK:
# `config:recommended` expands to include a catch-all
# `{ matchPackageNames: ["*"], semanticCommitType: "chore" }`, and `packageRules`
# outrank top-level config. Measured on the lane's first run — every subject
# `chore(deps)` while the config said `ci`, with every other key demonstrably in
# effect. So the property asks for it inside `packageRules`, which are appended
# after the preset's and win.
commit_type_is_scoped if {
	some rule in renovate.packageRules
	count(rule.semanticCommitType) > 0
}

violation contains {
	"rule": "one-bot-serves-every-ecosystem",
	"verdict": "V-RENOVATE-COMMIT-TYPE-UNSCOPED",
	"subjects": [{"path": "renovate.json5"}],
} if {
	governed
	renovate
	not commit_type_is_scoped
}

# 14. THE SET IS DATA AND SMALL ON PURPOSE. It names the ecosystems this
# repository actually maintains, so an absence is answerable at all — absence
# cannot be detected against an open world. An ecosystem nobody updates goes
# stale with nothing red anywhere, which is how one pinned toolchain sat twelve
# releases behind under a green weekly currency check.
maintained_ecosystems := ["cargo", "github-actions", "mise"]

violation contains {
	"rule": "one-bot-serves-every-ecosystem",
	"verdict": "V-ECOSYSTEM-UNSERVED",
	"subjects": [{"path": "renovate.json5"}, {"artifact": eco}],
} if {
	governed
	renovate
	some eco in maintained_ecosystems
	not eco in renovate.enabledManagers
}

# --- the fan-in is named, and the abandon spares it (property 17) -------------
#
# A red required check cancels the runs still spending on that commit. That
# saving has exactly one way to become a disaster: cancelling the run that
# carries the fan-in, which is the single context branch protection requires, so
# a cancelled one is a head that can never grade and never land.
#
# The exclusion is data, and data goes stale silently. Four assertions, and the
# last is the anti-vacuity term: the declared check is in the required roster,
# the declared workflow declares a job of that name, the abandon reads the
# declaration rather than a literal, and the lander actually calls it.

fanin_check := manifest.env.CI_FANIN_CHECK

fanin_workflow := manifest.env.CI_FANIN_WORKFLOW

violation contains {
	"rule": "fan-in-is-wired",
	"verdict": "V-FANIN-NOT-REQUIRED",
	"subjects": [{"path": "mise.toml"}, {"artifact": fanin_check}],
} if {
	governed
	not base_name(fanin_check) in roster_names
}

violation contains {
	"rule": "fan-in-is-wired",
	"verdict": "V-FANIN-WORKFLOW-DECLARES-NO-JOB",
	"subjects": [{"path": fanin_workflow}, {"artifact": fanin_check}],
} if {
	governed
	not fanin_job_declared
}

fanin_job_declared if {
	some key, job in workflow[fanin_workflow].jobs
	base_name(object.get(job, "name", key)) == base_name(fanin_check)
}

# THE DECLARATION IS READ, NOT RESTATED. A literal path in the abandon task would
# be a second authority for one fact, and the one that drifts is always the copy
# nobody edits. Read as LINES because these are shell programs, which no parser
# here builds a document for.
abandon_reads_declaration if {
	some line in input.tree.lines["mise-tasks/abandon-matrix.sh"]
	contains(line, "CI_FANIN_WORKFLOW")
}

violation contains {
	"rule": "fan-in-is-wired",
	"verdict": "V-ABANDON-RESTATES-THE-FANIN",
	"subjects": [{"path": "mise-tasks/abandon-matrix.sh"}],
} if {
	governed
	fanin_workflow
	not abandon_reads_declaration
}

# ANTI-VACUITY. Every assertion above is about making the abandon SAFE; none of
# them notices that it is never called. A mechanism nothing invokes passes each
# of them and saves nothing.
lander_calls_abandon if {
	some line in input.tree.lines["mise-tasks/land.sh"]
	contains(line, "abandon-matrix")
}

violation contains {
	"rule": "fan-in-is-wired",
	"verdict": "V-ABANDON-NEVER-CALLED",
	"subjects": [{"path": "mise-tasks/land.sh"}],
} if {
	governed
	fanin_workflow
	not lander_calls_abandon
}

# --- an unauthorised run is stopped before it spends (header property 7) -----
#
# The landing lease serialises landing, but it was enforced entirely inside the
# lander — so anything else pushing to a ready pull request bought a full matrix
# without ever touching the lock. Measured: four concurrent matrices while the
# lease changed hands three times, every holder honouring it.
#
# The remedy is a FIRST step in every job that can start immediately, and this is
# the sensor that no job is added without it. A job that installs a toolchain and
# then asks permission has already spent most of what asking was meant to save.
#
# Jobs with `needs:` are exempt for a REASON rather than by enumeration: a fan-in
# cannot start before its dependencies are terminal, so it can never spend a
# runner ahead of the cancellation.

lease_step_name := "Landing lease precondition"

starts_with_the_lease(path, name) if {
	workflow[path].jobs[name].steps[0].name == lease_step_name
}

violation contains {
	"rule": "lease-authorises-before-spending",
	"verdict": "V-LEASE-PRECONDITION-ABSENT",
	"subjects": [{"path": path}, {"artifact": name}],
} if {
	governed
	some path, _ in workflow
	on_pull_request(path)
	some name, job in workflow[path].jobs
	not job.needs
	not starts_with_the_lease(path, name)
}

# AND THE STEP MUST BE ALLOWED TO FAIL. The clause above matches the step's NAME,
# so a copy that reds its own job reads as present and correct. The precondition
# never exits non-zero by its own contract — but that promise is made by the
# fetched program, and the CALLER is what decides whether a body that will not
# PARSE is fatal. A truncated response or a bad edit makes the shell a syntax
# error in the FIRST step of every job: the step reds, the fan-in fails its
# dependencies, and the lander re-drafts on red — so one bad response re-drafts
# the whole fleet through the mechanism built to protect it.
#
# COUNTED rather than grepped for absence, because the two forms differ only by a
# suffix and a search for the bare spelling would pass a file carrying both.
lease_invocations(path) := count([line |
	some line in input.tree.lines[path]
	contains(line, "bash -c \"$body\"")
])

lease_tolerant(path) := count([line |
	some line in input.tree.lines[path]
	contains(line, "bash -c \"$body\" || exit 0")
])

violation contains {
	"rule": "lease-authorises-before-spending",
	"verdict": "V-LEASE-PRECONDITION-FATAL",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in input.tree.lines
	lease_invocations(path) > 0
	lease_invocations(path) != lease_tolerant(path)
}

# --- a workflow reading check status decides green through one predicate ------
#
# The green predicate has one home, and every hand-rolled copy of it so far has
# been the same defect: filtering out skipped runs counts a wholly skipped set as
# zero outstanding, i.e. green, which is exactly what a draft-era refresh looks
# like. Keyed to the check-runs ENDPOINT rather than to a banned spelling,
# because the spelling is what a rewrite changes and the fetch is what it cannot
# avoid.

reads_check_runs(path) if {
	some _, job in workflow[path].jobs
	some step in job.steps
	contains(object.get(step, "run", ""), "check-runs")
}

decides_through_checks_green(path) if {
	some _, job in workflow[path].jobs
	some step in job.steps
	contains(object.get(step, "run", ""), "checks-green")
}

violation contains {
	"rule": "check-status-decided-in-one-place",
	"verdict": "V-CHECK-STATUS-REROLLED",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in workflow
	reads_check_runs(path)
	not decides_through_checks_green(path)
}

# --- every branch a bot lands on has a watcher at the trigger ----------------
#
# A bot's pull requests are not landed by an agent: nothing runs on the bot's
# behalf unless a workflow is watching its heads. Handing an ecosystem to a bot
# without also pointing a lander at that bot's branch prefix is a complete,
# silent failure — the lane proposes, the pull requests accumulate, and no check
# anywhere is red about it. Measured twice, the second reproducing 84 seconds
# after the first was hand-landed.
#
# AT THE TRIGGER, NEVER A JOB CONDITION, which is the `workflow_run` finding
# reused rather than restated: a condition is evaluated after the run exists, so
# a lander scoped only there is not scoped.
#
# THE PREFIXES ARE READ FROM THE CONFIG THAT OWNS EACH LANE rather than assumed,
# and a lane whose config is absent is not asked for a watcher — no release
# config means no release pull requests to land.

bot_prefix("renovate.json5") := object.get(renovate, "branchPrefix", "renovate/")

bot_prefix("release-plz.toml") := object.get(release_config, ["pr", "pr_branch_prefix"], "release-plz-")

lane_is_live("renovate.json5") if renovate

lane_is_live("release-plz.toml") if release_config

watched(prefix) if {
	some path, _ in workflow
	some _, trigger in triggers(path)
	some branch in trigger.branches
	startswith(branch, prefix)
}

violation contains {
	"rule": "every-bot-branch-has-a-watcher",
	"verdict": "V-BOT-PREFIX-UNWATCHED",
	"subjects": [{"path": config}, {"artifact": bot_prefix(config)}],
} if {
	governed
	some config in ["renovate.json5", "release-plz.toml"]
	lane_is_live(config)
	not watched(bot_prefix(config))
}

# --- could not look -----------------------------------------------------------
#
# A DECLARED SOURCE THAT WOULD NOT PARSE is not an absent one. Absent is
# not-applicable — this tree runs no such workflow — and unparsed means the
# boundary tried and failed. Spelling those the same way is how a gate reports
# green over a file it never read.
violation contains {
	"rule": "ci-task-parity",
	"verdict": "V-CI-WORKFLOW-UNREAD",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	endswith(path, ".yml")
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# the documents these rules read, which is `crates/batten/tests/ci_parity.rs`'s
# job and the reason that file exists.

sound_manifest := {
	"tasks": {
		"verify": {"run": "mise run verify:gated\nmise run test:bats"},
		"verify:gated": {"run": "mise run lint"},
	},
	"env": {
		"CI_REQUIRED_CHECKS": "ci,final",
		"CI_FANIN_CHECK": "final",
		"CI_FANIN_WORKFLOW": ".github/workflows/ci.yml",
	},
}

# The lease step every job that can start immediately carries first.
lease_first := {"name": "Landing lease precondition", "run": "bash -c \"$body\" || exit 0"}

sound_workflow := {
	"on": {"pull_request": {"types": ["opened", "ready_for_review"]}},
	"jobs": {
		"ci": {
			"name": "ci",
			"runs-on": "ubuntu-latest",
			"steps": [lease_first, {"run": "mise run lint"}],
		},
		# The fan-in is exempt from the lease clause for a REASON rather than by
		# enumeration: it cannot start before its dependencies are terminal.
		"final": {
			"name": "final",
			"runs-on": "ubuntu-latest",
			"needs": ["ci"],
			"steps": [{"run": "echo done"}],
		},
	},
}

# The watcher every live bot lane owes, scoped at the TRIGGER.
sound_lander := {
	"on": {"workflow_run": {"branches": ["renovate/**", "release-plz-**"]}},
	"jobs": {"land": {"steps": [{"run": "mise run land"}]}},
}

sound_renovate := {
	"draftPR": true,
	"rebaseWhen": "behind-base-branch",
	"prConcurrentLimit": 1,
	"minimumReleaseAge": "3 days",
	"vulnerabilityAlerts": {"enabled": true},
	"packageRules": [{"semanticCommitType": "ci"}],
	"enabledManagers": ["cargo", "github-actions", "mise"],
}

sound_input := {"tree": {
	"documents": {
		"mise.toml": sound_manifest,
		".github/workflows/ci.yml": sound_workflow,
		".github/workflows/land.yml": sound_lander,
		"renovate.json5": sound_renovate,
		"release-plz.toml": {"pr": {"pr_draft": true}},
	},
	"lines": {
		"mise-tasks/abandon-matrix.sh": ["run=$CI_FANIN_WORKFLOW"],
		"mise-tasks/land.sh": ["mise run abandon-matrix"],
	},
	"tracked": ["mise.toml", ".github/workflows/ci.yml"],
	"missing": [],
}}

# The tree over `sound_input` with one document replaced.
swap(key, doc) := out if {
	docs := object.union(object.remove(sound_input.tree.documents, [key]), {key: doc})
	out := {"tree": object.union(object.remove(sound_input.tree, ["documents"]), {"documents": docs})}
}

test_a_sound_tree_is_clean if {
	count(violation) == 0 with input as sound_input
}

test_a_ci_task_verify_does_not_run_is_refused if {
	wf := {
		"on": {"pull_request": {"types": ["opened"]}},
		"jobs": {"ci": {"name": "ci", "runs-on": "ubuntu-latest", "steps": [{"run": "mise run smoke"}]}},
	}
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "V-CI-TASK-NOT-IN-VERIFY"
	some s in f.subjects
	s.artifact == "smoke"
}

# THE FOREIGN-RUNNER EXEMPTION, and it is an allowlist of foreign labels rather
# than of Linux ones: there is no local Windows, so the premise "a free local run
# would have caught it" is simply false there.
test_a_windows_job_may_run_a_task_verify_does_not if {
	wf := {
		"on": {"pull_request": {"types": ["opened"]}},
		"jobs": {"win": {"name": "win", "runs-on": "windows-latest", "steps": [{"run": "mise run smoke"}]}},
	}
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	every f in found {
		f.verdict != "V-CI-TASK-NOT-IN-VERIFY"
	}
}

# AN UNCLASSIFIED LABEL IS JUDGED. Exempting anything that is not `ubuntu-*`
# would switch the property off for `self-hosted` and for a matrix expression,
# which is the silent direction.
test_an_unclassified_runner_is_still_judged if {
	wf := {
		"on": {"pull_request": {"types": ["opened"]}},
		"jobs": {"odd": {"name": "odd", "runs-on": "self-hosted", "steps": [{"run": "mise run smoke"}]}},
	}
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "V-CI-TASK-NOT-IN-VERIFY"
}

# A TASK NAMED OUTSIDE A `run:` SCALAR IS NOT SPEND, which is the reading the
# retired program reached for with an `awk` that emitted `run:` lines only. These
# files name tasks in `name:`, in `env:` and at length in YAML comments — often
# to explain why a task is ABSENT — and a gate that fires on its own
# documentation is one people delete.
#
# PARSING SUBSUMES THE HARDER HALF rather than this clause carrying it: a YAML
# comment does not survive into the document at all, so the false-positive class
# the shell program had to exclude by hand cannot arise here. What is left to
# assert is that the reading is bounded to `run:`, which is what this case pins.
test_a_task_named_outside_a_run_step_is_not_read_as_spend if {
	wf := {
		"on": {"pull_request": {"types": ["opened"]}},
		"jobs": {"ci": {
			"name": "ci",
			"runs-on": "ubuntu-latest",
			"env": {"NOTE": "mise run smoke is deliberately not run here"},
			"steps": [{"name": "mise run smoke is not this step", "run": "mise run lint"}],
		}},
	}
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	every f in found {
		f.verdict != "V-CI-TASK-NOT-IN-VERIFY"
	}
}

test_a_job_missing_from_the_roster_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"extra": {"name": "extra", "runs-on": "ubuntu-latest", "steps": [{"run": "mise run lint"}]}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "V-JOB-NOT-IN-REQUIRED-ROSTER"
	some s in f.subjects
	s.artifact == "extra"
}

test_a_roster_name_matching_no_job_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_REQUIRED_CHECKS": "ci,final,ghost"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "V-REQUIRED-CHECK-NAMES-NO-JOB"
	some s in f.subjects
	s.artifact == "ghost"
}

# A MATRIX LEG MATCHES ON ITS BASE NAME: the runner appends the leg in
# parentheses and no committed text can expand it.
test_a_matrix_leg_matches_on_its_base_name if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_REQUIRED_CHECKS": "ci (ubuntu-latest),final"})})
	found := violation with input as swap("mise.toml", m)
	every f in found {
		f.verdict != "V-REQUIRED-CHECK-NAMES-NO-JOB"
	}
}

test_a_release_config_that_does_not_open_a_draft_is_refused if {
	found := violation with input as swap("release-plz.toml", {"pr": {"pr_draft": false}})
	some f in found
	f.verdict == "V-RELEASE-PR-NOT-DRAFT"
}

test_a_returned_dependabot_config_is_refused if {
	tree := object.union(sound_input.tree, {"tracked": ["mise.toml", ".github/dependabot.yml"]})
	found := violation with input as {"tree": tree}
	some f in found
	f.verdict == "V-DEPENDABOT-RETURNED"
}

test_each_renovate_bound_missing_is_refused if {
	some key in ["draftPR", "rebaseWhen", "prConcurrentLimit", "minimumReleaseAge", "vulnerabilityAlerts"]
	found := violation with input as swap("renovate.json5", object.remove(sound_renovate, [key]))
	some f in found
	f.verdict == "V-RENOVATE-BOUND-MISSING"
	some s in f.subjects
	s.artifact == key
}

# REVERTING `rebaseWhen` TO `never` IS THE REGRESSION, not merely a missing key:
# a draft head grades nothing, so rebasing it is free, and a head nobody rebases
# goes behind the trunk where a fast-forward is arithmetically unavailable.
test_reverting_rebase_when_to_never_is_refused if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"rebaseWhen": "never"}))
	some f in found
	f.verdict == "V-RENOVATE-BOUND-MISSING"
}

# ZERO IS UNLIMITED, so the bound and its own negation differ by one character.
test_a_zero_concurrent_limit_is_not_a_bound if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"prConcurrentLimit": 0}))
	some f in found
	f.verdict == "V-RENOVATE-BOUND-MISSING"
}

test_a_top_level_commit_type_does_not_satisfy_the_scoped_one if {
	stripped := object.remove(sound_renovate, ["packageRules"])
	found := violation with input as swap("renovate.json5", object.union(stripped, {"semanticCommitType": "ci"}))
	some f in found
	f.verdict == "V-RENOVATE-COMMIT-TYPE-UNSCOPED"
}

test_an_unserved_ecosystem_is_refused_and_named if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"enabledManagers": ["cargo", "github-actions"]}))
	some f in found
	f.verdict == "V-ECOSYSTEM-UNSERVED"
	some s in f.subjects
	s.artifact == "mise"
}

test_a_fanin_outside_the_roster_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_FANIN_CHECK": "nowhere"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "V-FANIN-NOT-REQUIRED"
}

test_a_fanin_workflow_declaring_no_such_job_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_FANIN_WORKFLOW": ".github/workflows/other.yml"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "V-FANIN-WORKFLOW-DECLARES-NO-JOB"
}

test_an_abandon_that_restates_the_path_is_refused if {
	lines := object.union(sound_input.tree.lines, {"mise-tasks/abandon-matrix.sh": ["run=.github/workflows/ci.yml"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "V-ABANDON-RESTATES-THE-FANIN"
}

# THE ANTI-VACUITY TERM. Every other fan-in clause makes the abandon SAFE; none
# of them notices it is never called.
test_a_lander_that_never_abandons_is_refused if {
	lines := object.union(sound_input.tree.lines, {"mise-tasks/land.sh": ["mise run ci-wait"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "V-ABANDON-NEVER-CALLED"
}

test_a_job_that_starts_without_asking_the_lease_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"ci": {
		"name": "ci",
		"runs-on": "ubuntu-latest",
		"steps": [{"run": "mise run lint"}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "V-LEASE-PRECONDITION-ABSENT"
	some sub in f.subjects
	sub.artifact == "ci"
}

# THE PRECONDITION MUST BE FIRST. A job that installs a toolchain and then asks
# permission has already spent most of what asking was meant to save.
test_a_lease_step_that_is_not_first_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"ci": {
		"name": "ci",
		"runs-on": "ubuntu-latest",
		"steps": [{"run": "install"}, lease_first],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "V-LEASE-PRECONDITION-ABSENT"
}

# A FAN-IN IS EXEMPT, and for a reason rather than by name: it cannot start
# before its dependencies are terminal, so it can never spend ahead of the
# cancellation.
test_a_job_that_waits_on_another_is_not_asked_for_the_lease if {
	found := violation with input as sound_input
	every f in found {
		f.verdict != "V-LEASE-PRECONDITION-ABSENT"
	}
}

# COUNTED, NOT SEARCHED FOR ABSENCE: the two forms differ only by a suffix, so a
# file carrying both would pass a bare search.
test_a_precondition_invoked_without_the_tolerant_suffix_is_refused if {
	lines := object.union(sound_input.tree.lines, {".github/workflows/ci.yml": ["        bash -c \"$body\""]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "V-LEASE-PRECONDITION-FATAL"
}

test_a_workflow_reading_check_runs_without_the_one_predicate_is_refused if {
	wf := object.union(sound_lander, {"jobs": {"land": {"steps": [{"run": "gh api /check-runs | jq ."}]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	some f in found
	f.verdict == "V-CHECK-STATUS-REROLLED"
}

test_a_workflow_deciding_through_the_one_predicate_passes if {
	wf := object.union(sound_lander, {"jobs": {"land": {"steps": [{"run": "gh api /check-runs && mise run checks-green"}]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	every f in found {
		f.verdict != "V-CHECK-STATUS-REROLLED"
	}
}

# A WORKFLOW THAT NEVER READS CHECK STATUS is not asked for the predicate.
test_a_workflow_that_reads_no_check_status_is_not_asked if {
	found := violation with input as sound_input
	every f in found {
		f.verdict != "V-CHECK-STATUS-REROLLED"
	}
}

test_a_bot_prefix_with_no_watcher_is_refused if {
	wf := object.union(sound_lander, {"on": {"workflow_run": {"branches": ["release-plz-**"]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	some f in found
	f.verdict == "V-BOT-PREFIX-UNWATCHED"
	some sub in f.subjects
	sub.artifact == "renovate/"
}

# THE PREFIX IS READ FROM THE CONFIG THAT OWNS IT, never assumed.
test_an_overridden_prefix_is_read_from_its_own_config if {
	docs := object.union(sound_input.tree.documents, {
		"renovate.json5": object.union(sound_renovate, {"branchPrefix": "bot/"}),
		".github/workflows/land.yml": object.union(sound_lander, {"on": {"workflow_run": {"branches": ["bot/**", "release-plz-**"]}}}),
	})
	found := violation with input as {"tree": object.union(sound_input.tree, {"documents": docs})}
	every f in found {
		f.verdict != "V-BOT-PREFIX-UNWATCHED"
	}
}

# A LANE WHOSE CONFIG IS ABSENT IS NOT ASKED FOR A WATCHER: no release config
# means no release pull requests to land.
# `object.union` is a DEEP merge, so a document "removed" by unioning a smaller
# map straight back over the tree is not removed at all. Built by replacing the
# `documents` key wholesale for that reason — the same trap that made two
# fixtures in the sibling preset silently identical to the clean one.
test_a_lane_with_no_config_is_not_asked_for_a_watcher if {
	lander := {"on": {"workflow_run": {"branches": ["renovate/**"]}}, "jobs": {"land": {"steps": [{"run": "mise run land"}]}}}
	docs := object.union(
		object.remove(sound_input.tree.documents, ["release-plz.toml", ".github/workflows/land.yml"]),
		{".github/workflows/land.yml": lander},
	)
	tree := object.union(object.remove(sound_input.tree, ["documents"]), {"documents": docs})
	found := violation with input as {"tree": tree}
	every f in found {
		f.verdict != "V-BOT-PREFIX-UNWATCHED"
	}
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT.
test_a_tree_with_no_verify_task_is_not_this_rules_business if {
	found := violation with input as {"tree": {"documents": {}, "lines": {}, "tracked": [], "missing": []}}
	count(found) == 0
}

# COULD NOT LOOK STAYS LOUD, and is spelled differently from not-applicable.
test_an_unreadable_workflow_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"tracked": [],
		"missing": [".github/workflows/ci.yml"],
	}}
	some f in found
	f.verdict == "V-CI-WORKFLOW-UNREAD"
}
