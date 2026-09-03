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
#MUTANT-OWNER CLOUD-989|the mutation applies and alters reachable code, and the case it names cannot observe the change — a downstream guard or a second arm masks it. That is a defect in the DECLARATION, which `SURVIVED` mis-attributes to the suite; CLOUD-989's fork is what reports it correctly, and these are the live instances its own acceptance says it lacked
#MUTANT roster-may-miss-a-job|s@not job_in_roster(name)@false@|a_pull_request_job_missing_from_the_roster_is_refused
#MUTANT roster-may-name-a-ghost|s@not roster_name_has_a_job(name)@false@|a_roster_name_matching_no_job_is_refused
#MUTANT dependabot-may-return|s@not dependabot_absent@false@|a_returned_dependabot_config_is_refused
#MUTANT cache-path-may-carry-the-base|s@^\tpath_varies_between_runs(step)$@\tfalse@|a_cached_path_carrying_an_expression_is_refused
#MUTANT lander-may-not-abandon|s@not lander_calls_abandon@false@|a_lander_that_never_abandons_is_refused
#
#MUTANT-SUITE crates/batten/tests/it/ci_parity.rs

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

rules contains "foreign-cargo-is-the-declared-spelling"

rules contains "cache-path-is-rebase-stable"

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
	"verdict": "task run missing",
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
	"verdict": "check name unknown",
	"subjects": [{"path": "mise.toml"}, {"artifact": name}],
} if {
	governed
	some name in roster_names
	not roster_name_has_a_job(name)
}

violation contains {
	"rule": "required-roster-matches-jobs",
	"verdict": "job list missing",
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
	"verdict": "release open early",
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
	"verdict": "config carry duplicate",
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
	"verdict": "bound declare missing",
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
	"verdict": "commit name unnamed",
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
	"verdict": "manifest cover missing",
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
	"verdict": "job require missing",
	"subjects": [{"path": "mise.toml"}, {"artifact": fanin_check}],
} if {
	governed
	not base_name(fanin_check) in roster_names
}

violation contains {
	"rule": "fan-in-is-wired",
	"verdict": "workflow declare empty",
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
	"verdict": "job declare duplicate",
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
	"verdict": "job reach dead",
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
	"verdict": "lease guard absent",
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
	"verdict": "lease guard unsafe",
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
	"verdict": "check grade twice",
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
	"verdict": "branch watch missing",
	"subjects": [{"path": config}, {"artifact": bot_prefix(config)}],
} if {
	governed
	some config in ["renovate.json5", "release-plz.toml"]
	lane_is_live(config)
	not watched(bot_prefix(config))
}

# --- a cached path holds still across a rebase (CLOUD-1342) -------------------
#
# `actions/cache` identifies an entry by key AND VERSION, and it defines version
# as "a hash generated for a combination of compression tool used … and the
# `path` of directories being cached". So a `path` carrying a workflow EXPRESSION
# is a path that can differ between two runs of the same job — and when it does,
# the entry the first run saved is unreachable to the second whatever its key
# says. The miss is total and it is silent: the step reports `Cache not found`
# and the job simply does the work again.
#
# MEASURED, AND THE FIRST DIAGNOSIS BLAMED THE WRONG HALF. The `perf` job cached
# `target/perf/base-<merge base>`, interpolated; `land` rebases every lap, so the
# merge base moved on every lap and the entry's identity moved with it — 4 runs
# across 2 pull requests, ZERO hits, ~190 MB written and discarded each time. The
# remedy first written down was to drop the SHA from the KEY, which would have
# changed nothing whatever, because the path had already put the entry out of
# reach. That wrong turn is why this is a predicate and not a comment: the defect
# costs a full build every run, is invisible in the job log, and reads exactly
# like a cache that has not been populated yet.
#
# THE KEY IS DELIBERATELY NOT JUDGED. An expression BELONGS in a key — telling
# one entry from another is what a key is FOR — so a rule over both halves would
# refuse the one shape that works. An earlier draft of this paragraph justified
# that with "a key that never moves never SAVES", which is true of the action in
# general and is NOT the reason here: this repository's own `perf` job now
# restores and never saves, so its key carries no expression at all and is
# correct. The path is the half that has to hold still; that is the whole claim.
#
# ALL THREE SPELLINGS ARE THE SAME ACTION. `actions/cache/restore` and
# `actions/cache/save` derive an entry's version from `path` exactly as the
# composite `actions/cache` does, so an interpolated path is the identical silent
# total miss. Matching only the composite spelling would have left this predicate
# live and reaching nothing the moment a job split restore from save — which is
# precisely what CLOUD-1342 does.

cache_action(step) if cache_uses(object.get(step, "uses", ""))

cache_uses(uses) if startswith(uses, "actions/cache@")

cache_uses(uses) if startswith(uses, "actions/cache/")

path_varies_between_runs(step) if contains(object.get(step, ["with", "path"], ""), "${{")

violation contains {
	"rule": "cache-path-is-rebase-stable",
	"verdict": "path reach dead",
	"subjects": [{"path": path}, {"artifact": name}],
} if {
	governed
	some path, _ in workflow
	some name, job in workflow[path].jobs
	some step in job.steps
	cache_action(step)
	path_varies_between_runs(step)
}

# --- could not look -----------------------------------------------------------
#
# A DECLARED SOURCE THAT WOULD NOT PARSE is not an absent one. Absent is
# not-applicable — this tree runs no such workflow — and unparsed means the
# boundary tried and failed. Spelling those the same way is how a gate reports
# green over a file it never read.
violation contains {
	"rule": "ci-task-parity",
	"verdict": "workflow read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	endswith(path, ".yml")
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# the documents these rules read, which is `crates/batten/tests/ci_parity.rs`'s
# job and the reason that file exists.

# --- a foreign runner's cargo invocation is `test:cargo`'s own ----------------
#
# CLOUD-662, and the last of `ci-local-parity`'s forty predicates to port
# (CLOUD-1161). The task-parity property above exempts a foreign runner, and
# correctly: there is no local Windows, so "a free local run would have caught
# it" is simply false there. What that exemption COSTS is this — the foreign
# job's command is a second spelling of `test:cargo`'s body, accurate today and
# only today. Change the task and every Linux leg follows it while the foreign
# leg keeps running the old command, green on work it no longer covers.
# `ci-task-parity` cannot object, because its exemption is per JOB, not per
# property.
#
# WHY THIS READS THE MANIFEST RATHER THAN `mise tasks info`, stated because the
# retired program refused to: it objected that a second reader of the task body
# is a second AUTHORITY over a graph mise owns, and that objection is real. What
# makes it affordable here is that the two readings are the same bytes —
# `test:cargo` carries no template, no `depends` body and no argument
# substitution, so `mise tasks info --json`'s `.run` IS the manifest string. The
# bound is exactly that: the day `test:cargo` grows a template, this reads the
# unexpanded form and the two authorities can disagree. A module cannot spawn
# (`RuleKind::scopes` pairs every spawning kind with `RuleScope::Tree`), so the
# alternative was not a better reading — it was no gate at all.
#
# NO REGEX, AND THAT IS NOT A REGISTRY DODGE. The shapes here are two fixed
# affixes, so `startswith`/`trim_prefix` decide them exactly; a `[[pattern]]` row
# would add a spelling to look up without adding anything to decide.

# The task's own cargo invocation, lifted out of the `if ! <cmd>; then exit 1; fi`
# guard the body wraps it in. A partial rule rather than a function: a body with
# no such line yields nothing, which is what the could-not-look clause reads.
task_cargo contains cmd if {
	body := object.get(manifest.tasks, ["test:cargo", "run"], "")
	some raw in split(body, "\n")
	trimmed := trim_space(raw)
	startswith(trimmed, "if ! cargo ")
	endswith(trimmed, "; then exit 1; fi")
	cmd := trim_suffix(trim_prefix(trimmed, "if ! "), "; then exit 1; fi")
}

# Every foreign-runner cargo invocation, EXCLUDING a `--no-run` build. A build
# that compiles and executes nothing cannot go green on work it no longer
# covers, because it covers none. That exemption also defends itself: a job
# gaining `--no-run` drops out of the anti-vacuity term below, so the tree
# refuses rather than silently ceasing to test.
foreign_cargo contains [path, number, cmd] if {
	some path, file_lines in input.tree.lines
	some index, line in file_lines
	not contains(line, " --no-run")
	stripped := trim_prefix(trim_space(line), "- ")
	startswith(stripped, "run: mise exec -- cargo ")
	cmd := trim_space(trim_prefix(stripped, "run:"))
	number := index + 1
}

violation contains {
	"rule": "foreign-cargo-is-the-declared-spelling",
	"verdict": "cargo spelling other",
	"subjects": [{"path": path, "line": number}, {"artifact": cmd}],
} if {
	governed
	some [path, number, cmd] in foreign_cargo
	some declared in task_cargo
	cmd != concat("", ["mise exec -- ", declared])
}

# COULD-NOT-LOOK IS A FAILURE, NEVER A PASS, for the reason a dead gate and a
# clean tree are byte-identical on the decision surface. Both arms are guarded on
# the manifest actually declaring `test:cargo`: a tree that runs no cargo suite
# is not answering this question, and refusing it would fire on every fixture
# that carries a copy of this config and none of its subjects.
violation contains {
	"rule": "foreign-cargo-is-the-declared-spelling",
	"verdict": "cargo reach absent",
	"subjects": [{"count": 0}],
} if {
	governed
	manifest.tasks["test:cargo"]
	count(task_cargo) > 0
	count(foreign_cargo) == 0
}

violation contains {
	"rule": "foreign-cargo-is-the-declared-spelling",
	"verdict": "task read unread",
	"subjects": [{"artifact": "test:cargo"}],
} if {
	governed
	manifest.tasks["test:cargo"]
	count(task_cargo) == 0
}

sound_manifest := {
	"tasks": {
		"verify": {"run": "mise run verify:gated\nmise run test:bats"},
		"verify:gated": {"run": "mise run lint"},
		"test:cargo": {"run": "if ! cargo nextest run --workspace; then exit 1; fi"},
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
		# The foreign leg the anti-vacuity term needs a subject from: without it a
		# clean fixture would be clean because nothing was looked at.
		".github/workflows/rust.yml": ["      - run: mise exec -- cargo nextest run --workspace"],
	},
	"tracked": ["mise.toml", ".github/workflows/ci.yml"],
	"missing": {},
}}

# The tree over `sound_input` with one document replaced.
swap(key, doc) := out if {
	docs := object.union(object.remove(sound_input.tree.documents, [key]), {key: doc})
	out := {"tree": object.union(object.remove(sound_input.tree, ["documents"]), {"documents": docs})}
}

# --- the foreign cargo spelling ----------------------------------------------

# A foreign leg running something `test:cargo` does not declare is the whole
# defect: the Linux legs follow the task, this one does not, and `ci-task-parity`
# cannot see it because its exemption is per job.
test_a_foreign_leg_running_a_different_cargo_is_refused if {
	drifted := object.union(sound_input.tree.lines, {".github/workflows/rust.yml": ["      - run: mise exec -- cargo nextest run --workspace --all-features"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": drifted})}
	some f in found
	f.verdict == "cargo spelling other"
}

# THE ANTI-VACUITY TERM. Every clause above judges a foreign leg; none of them
# fires when there is no foreign leg to judge, and a tree that lost its Windows
# coverage would report clean for exactly that reason.
test_a_tree_with_no_foreign_cargo_leg_is_refused if {
	# `object.union` is a DEEP merge, so unioning `{"lines": {}}` over the tree
	# KEEPS every existing key and removes nothing — the removal has to be an
	# explicit `object.remove` or this case tests the sound tree twice.
	blank := object.union(object.remove(sound_input.tree, ["lines"]), {"lines": {}})
	found := violation with input as {"tree": blank}
	some f in found
	f.verdict == "cargo reach absent"
}

# A `--no-run` build compiles and executes nothing, so it covers nothing and
# cannot drift onto work it no longer covers. It is exempt from the comparison
# AND does not count toward the term above, so a leg that gains `--no-run`
# refuses rather than silently ceasing to test.
test_a_no_run_build_is_exempt_and_does_not_satisfy_the_term if {
	only_no_run := object.union(sound_input.tree.lines, {".github/workflows/rust.yml": ["      - run: mise exec -- cargo nextest run --no-run --workspace"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": only_no_run})}
	some f in found
	f.verdict == "cargo reach absent"
}

# A manifest whose `test:cargo` carries no readable cargo line is could-not-look,
# never a pass: the comparison has lost its right-hand side.
test_a_task_yielding_no_cargo_line_is_refused if {
	blind := object.union(sound_manifest.tasks, {"test:cargo": {"run": "./mise-tasks/step-receipt.sh check test:cargo"}})
	found := violation with input as swap("mise.toml", object.union(sound_manifest, {"tasks": blind}))
	some f in found
	f.verdict == "task read unread"
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
	f.verdict == "task run missing"
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
		f.verdict != "task run missing"
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
	f.verdict == "task run missing"
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
		f.verdict != "task run missing"
	}
}

test_a_job_missing_from_the_roster_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"extra": {"name": "extra", "runs-on": "ubuntu-latest", "steps": [{"run": "mise run lint"}]}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "job list missing"
	some s in f.subjects
	s.artifact == "extra"
}

test_a_roster_name_matching_no_job_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_REQUIRED_CHECKS": "ci,final,ghost"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "check name unknown"
	some s in f.subjects
	s.artifact == "ghost"
}

# A MATRIX LEG MATCHES ON ITS BASE NAME: the runner appends the leg in
# parentheses and no committed text can expand it.
test_a_matrix_leg_matches_on_its_base_name if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_REQUIRED_CHECKS": "ci (ubuntu-latest),final"})})
	found := violation with input as swap("mise.toml", m)
	every f in found {
		f.verdict != "check name unknown"
	}
}

test_a_release_config_that_does_not_open_a_draft_is_refused if {
	found := violation with input as swap("release-plz.toml", {"pr": {"pr_draft": false}})
	some f in found
	f.verdict == "release open early"
}

test_a_returned_dependabot_config_is_refused if {
	tree := object.union(sound_input.tree, {"tracked": ["mise.toml", ".github/dependabot.yml"]})
	found := violation with input as {"tree": tree}
	some f in found
	f.verdict == "config carry duplicate"
}

test_each_renovate_bound_missing_is_refused if {
	some key in ["draftPR", "rebaseWhen", "prConcurrentLimit", "minimumReleaseAge", "vulnerabilityAlerts"]
	found := violation with input as swap("renovate.json5", object.remove(sound_renovate, [key]))
	some f in found
	f.verdict == "bound declare missing"
	some s in f.subjects
	s.artifact == key
}

# REVERTING `rebaseWhen` TO `never` IS THE REGRESSION, not merely a missing key:
# a draft head grades nothing, so rebasing it is free, and a head nobody rebases
# goes behind the trunk where a fast-forward is arithmetically unavailable.
test_reverting_rebase_when_to_never_is_refused if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"rebaseWhen": "never"}))
	some f in found
	f.verdict == "bound declare missing"
}

# ZERO IS UNLIMITED, so the bound and its own negation differ by one character.
test_a_zero_concurrent_limit_is_not_a_bound if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"prConcurrentLimit": 0}))
	some f in found
	f.verdict == "bound declare missing"
}

test_a_top_level_commit_type_does_not_satisfy_the_scoped_one if {
	stripped := object.remove(sound_renovate, ["packageRules"])
	found := violation with input as swap("renovate.json5", object.union(stripped, {"semanticCommitType": "ci"}))
	some f in found
	f.verdict == "commit name unnamed"
}

test_an_unserved_ecosystem_is_refused_and_named if {
	found := violation with input as swap("renovate.json5", object.union(sound_renovate, {"enabledManagers": ["cargo", "github-actions"]}))
	some f in found
	f.verdict == "manifest cover missing"
	some s in f.subjects
	s.artifact == "mise"
}

test_a_fanin_outside_the_roster_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_FANIN_CHECK": "nowhere"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "job require missing"
}

test_a_fanin_workflow_declaring_no_such_job_is_refused if {
	m := object.union(sound_manifest, {"env": object.union(sound_manifest.env, {"CI_FANIN_WORKFLOW": ".github/workflows/other.yml"})})
	found := violation with input as swap("mise.toml", m)
	some f in found
	f.verdict == "workflow declare empty"
}

test_an_abandon_that_restates_the_path_is_refused if {
	lines := object.union(sound_input.tree.lines, {"mise-tasks/abandon-matrix.sh": ["run=.github/workflows/ci.yml"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "job declare duplicate"
}

# THE ANTI-VACUITY TERM. Every other fan-in clause makes the abandon SAFE; none
# of them notices it is never called.
test_a_lander_that_never_abandons_is_refused if {
	lines := object.union(sound_input.tree.lines, {"mise-tasks/land.sh": ["mise run ci-wait"]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "job reach dead"
}

test_a_job_that_starts_without_asking_the_lease_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"ci": {
		"name": "ci",
		"runs-on": "ubuntu-latest",
		"steps": [{"run": "mise run lint"}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "lease guard absent"
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
	f.verdict == "lease guard absent"
}

# --- a cached path holds still across a rebase --------------------------------

# The landed defect, as a case: an interpolated path moves the entry's VERSION,
# so the entry a previous run saved cannot be found however the key is spelled.
test_a_cached_path_carrying_an_expression_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"perf": {
		"name": "perf",
		"runs-on": "ubuntu-latest",
		"steps": [lease_first, {
			"uses": "actions/cache@v6.1.0",
			"with": {"path": "target/perf/base-${{ steps.base.outputs.sha }}", "key": "perf-base"},
		}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "path reach dead"
	some sub in f.subjects
	sub.artifact == "perf"
}

# THE KEY IS NOT THE SUBJECT, and this is the case that says so. An expression in
# a key is how one entry is told from another, so a predicate that fired here
# would refuse a working shape along with the defect.
test_an_expression_in_the_key_alone_is_clean if {
	wf := object.union(sound_workflow, {"jobs": {"perf": {
		"name": "perf",
		"runs-on": "ubuntu-latest",
		"steps": [lease_first, {
			"uses": "actions/cache@v6.1.0",
			"with": {"path": "target/perf/base-seed", "key": "perf-base-${{ steps.base.outputs.sha }}"},
		}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	every f in found {
		f.verdict != "path reach dead"
	}
}

# THE SUB-ACTION SPELLING IS THE SAME DEFECT, and this is the case that keeps the
# predicate from going dead the moment a job splits restore from save. CLOUD-1342
# does exactly that split, so without this arm the rule would load clean and
# reach nothing in the repository it is registered against.
test_a_restore_only_step_carrying_an_expression_is_refused if {
	wf := object.union(sound_workflow, {"jobs": {"perf": {
		"name": "perf",
		"runs-on": "ubuntu-latest",
		"steps": [lease_first, {
			"uses": "actions/cache/restore@v6.1.0",
			"with": {"path": "target/perf/base-${{ steps.base.outputs.sha }}", "key": "perf-base"},
		}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	some f in found
	f.verdict == "path reach dead"
}

# A STEP THAT IS NOT THIS ACTION IS NOT THIS RULE'S BUSINESS. `rust-cache` takes
# no `path` at all, and a rule reading every step's `with.path` would judge an
# upload or a checkout on a question that does not apply to it.
test_another_action_interpolating_a_path_is_not_judged if {
	wf := object.union(sound_workflow, {"jobs": {"perf": {
		"name": "perf",
		"runs-on": "ubuntu-latest",
		"steps": [lease_first, {
			"uses": "actions/upload-artifact@v4",
			"with": {"path": "out/${{ github.run_id }}"},
		}],
	}}})
	found := violation with input as swap(".github/workflows/ci.yml", wf)
	every f in found {
		f.verdict != "path reach dead"
	}
}

# THE SOUND TREE IS SILENT, which is the arm that keeps the rule from being one
# that fires on everything and therefore decides nothing.
test_a_sound_tree_has_no_varying_cache_path if {
	found := violation with input as sound_input
	every f in found {
		f.verdict != "path reach dead"
	}
}

# A FAN-IN IS EXEMPT, and for a reason rather than by name: it cannot start
# before its dependencies are terminal, so it can never spend ahead of the
# cancellation.
test_a_job_that_waits_on_another_is_not_asked_for_the_lease if {
	found := violation with input as sound_input
	every f in found {
		f.verdict != "lease guard absent"
	}
}

# COUNTED, NOT SEARCHED FOR ABSENCE: the two forms differ only by a suffix, so a
# file carrying both would pass a bare search.
test_a_precondition_invoked_without_the_tolerant_suffix_is_refused if {
	lines := object.union(sound_input.tree.lines, {".github/workflows/ci.yml": ["        bash -c \"$body\""]})
	found := violation with input as {"tree": object.union(sound_input.tree, {"lines": lines})}
	some f in found
	f.verdict == "lease guard unsafe"
}

test_a_workflow_reading_check_runs_without_the_one_predicate_is_refused if {
	wf := object.union(sound_lander, {"jobs": {"land": {"steps": [{"run": "gh api /check-runs | jq ."}]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	some f in found
	f.verdict == "check grade twice"
}

test_a_workflow_deciding_through_the_one_predicate_passes if {
	wf := object.union(sound_lander, {"jobs": {"land": {"steps": [{"run": "gh api /check-runs && mise run checks-green"}]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	every f in found {
		f.verdict != "check grade twice"
	}
}

# A WORKFLOW THAT NEVER READS CHECK STATUS is not asked for the predicate.
test_a_workflow_that_reads_no_check_status_is_not_asked if {
	found := violation with input as sound_input
	every f in found {
		f.verdict != "check grade twice"
	}
}

test_a_bot_prefix_with_no_watcher_is_refused if {
	wf := object.union(sound_lander, {"on": {"workflow_run": {"branches": ["release-plz-**"]}}})
	found := violation with input as swap(".github/workflows/land.yml", wf)
	some f in found
	f.verdict == "branch watch missing"
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
		f.verdict != "branch watch missing"
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
		f.verdict != "branch watch missing"
	}
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT.
test_a_tree_with_no_verify_task_is_not_this_rules_business if {
	found := violation with input as {"tree": {"documents": {}, "lines": {}, "tracked": [], "missing": {}}}
	count(found) == 0
}

# COULD NOT LOOK STAYS LOUD, and is spelled differently from not-applicable.
test_an_unreadable_workflow_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"tracked": [],
		"missing": {".github/workflows/ci.yml": "absent"},
	}}
	some f in found
	f.verdict == "workflow read unread"
}
