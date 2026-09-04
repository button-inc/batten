# A CI job that builds Rust must declare a cache, and a cache key must be
# readable (CLOUD-1410, CLOUD-1408).
#
# THE DEFECT CLASS, AND WHY NOTHING SAW IT. Three separate cache failures landed
# in this tree and every gate was green over all three:
#
#   * `commit-lint.yml` forked `cargo` from a workflow declaring no
#     `Swatinem/rust-cache` step at all, so a required check spent ~340s
#     cold-building a binary to run a 758ms lint. CLOUD-812 narrowed that
#     workflow's tool installs and the cargo cache was simply never in anybody's
#     scope afterwards.
#   * every one of 12 `shared-key` values ended in
#     `-${{ hashFiles('Cargo.toml') }}`. `shared-key` is applied at
#     `Swatinem/rust-cache` `config.ts:77`, INSIDE the prefix assigned to
#     `restoreKey` at `:133` — so the hash did not merely miss the exact key, it
#     moved the fallback and nothing in the store matched.
#   * `bats` read a family (`bats-`) nothing on `main` ever wrote, while writing
#     multi-gigabyte entries under `refs/pull/N/merge` that no other pull request
#     can read.
#
# WHY NO EXISTING GATE REACHES ANY OF THEM. `ci-parity.rego` mentions
# `rust-cache` only to exclude it — "A STEP THAT IS NOT THIS ACTION IS NOT THIS
# RULE'S BUSINESS" — and `ci-tools-check` judges `mise-action` tool narrowing,
# which has nothing to say about caching. `ci-suite-lane` reads the same workflow
# document and answers a different question. So all three failures were
# expressible, none was checkable, and each cost real minutes on every pull
# request until somebody read a job log by hand.
#
# ALL THREE ARE SILENT, WHICH IS WHAT MAKES THEM A DENY. A cache that misses is
# not red and is not louder — it is a green run that took longer, and the only
# symptom is in a bill nobody reads. That is the same asymmetry `ci-suite-lane`
# is stated over.
#
# THE PARSED DOCUMENT, NOT THE LINES, FOR EVERY DECISION. A `shared-key` and the
# `uses:` that would justify it are in different steps of the same job, and a
# job's trigger is a top-level key tens of lines away — the questions are
# structural, and a line-oriented reading cannot say which job anything belongs
# to. `input.tree.lines` is read for POINTERS ONLY, which is rule 4's shape here:
# the finding carries `{path, line}` and never the key's value, because a
# `shared-key` is consumer config and a CI log is a public surface.
#
#MUTANT-SUITE crates/batten/tests/it/ci_cache_declared.rs
#MUTANT key-may-carry-a-hash|s@contains(key, "hashFiles")@false@|a_shared_key_carrying_a_content_hash_is_refused
#MUTANT cargo-reach-may-go-uncached|s@not declares_a_cache(path, name)@false@|a_cargo_job_with_no_cache_step_is_refused
#MUTANT warmed-family-may-be-written|s@not reads_only(step)@false@|a_pull_request_writer_of_a_warmed_family_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_cache_declared

import rego.v1

rules contains "cache-key-carries-a-content-hash"

rules contains "cargo-reach-declares-a-cache"

rules contains "warmed-family-is-read-only"

# --- what is being judged, and whether there is anything to judge -------------

# THE MANIFEST IS READ INLINE, NEVER BOUND TO A TOP-LEVEL RULE, AND THAT IS A
# MEASURED WORKAROUND RATHER THAN A STYLE CHOICE.
#
# Measured 2026-09-04 over the compiled engine: a module carrying
# `manifest := input.tree.documents["mise.toml"]` goes ENTIRELY SILENT — every
# predicate, including one whose body is `true` — whenever the manifest declares
# a task named `deny`, which this repository's own `mise.toml` does
# (`[tasks.deny]`, cargo-deny). Reduced to twenty lines: an unconditional
# `violation` plus a top-level rule bound to any object carrying a `deny` key is
# silent, and the same read written INLINE at each use site speaks. `opa eval`
# over the identical input returns the three expected findings, so the divergence
# is the engine's evaluator rather than the policy.
#
# The shape to avoid is a top-level rule whose VALUE can contain a `deny` key —
# `data.batten.deny` being the composed set the engine reads is the obvious
# suspect, and the exact mechanism is not established here. What is established
# is that the failure is silent, total, and indistinguishable from a clean tree
# on the decision surface, which is the dead-gate class this repository keeps
# re-meeting. `policy/ci-parity.rego` carries the same `manifest :=` binding and
# so has the same shape; whether it is silenced today was not measured.
workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

# The guard, for `hk-fix-selection`'s measured reason: an unguarded module
# reported seven findings against a fixture carrying a copy of the config and
# none of its subjects. A tree with no workflow declaring jobs is answering for
# nothing here.
governed if count(object.keys(workflow)) > 0

triggers(path) := t if {
	t := workflow[path].on
	is_object(t)
}

on_pull_request(path) if _ := triggers(path).pull_request

# `push` ONLY, AND NOT `schedule`, WHICH IS A DELIBERATE BOUND rather than an
# oversight. "Warmed" here means an entry a pull request can actually READ, and
# GitHub scopes a cache read to the run's own ref plus the base branch — so what
# matters is a writer on the trunk, which in this repository is a push-triggered
# workflow. The scheduled workflows do write `perf-`, `coverage-` and `fuzz-`,
# and those families are outside this predicate on purpose: `perf`'s base arm is
# a separate cache keyed to the merge base, which CLOUD-1331 and CLOUD-1342
# already settled, and refusing it here would re-open a decision made elsewhere.
on_push(path) if _ := triggers(path).push

# --- the steps, and the two facts a cache step carries ------------------------

# A SET OF TRIPLES RATHER THAN A PARTIAL OBJECT, because a job's identity is
# the (workflow, job name) PAIR and Rego has no composite key for that shape.
# `ci_task_used` in `ci-parity.rego` is the same construction for the same
# reason.
job_step contains [path, name, step] if {
	some path, _ in workflow
	some name, job in workflow[path].jobs
	some step in job.steps
}

job_of contains [path, name] if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
}

# THE ACTION, BY REPOSITORY RATHER THAN BY PINNED DIGEST. Every step in this tree
# is pinned `@6323deb1 # v2.9.2` and a digest comparison would go silently blind
# the day one is bumped — the direction that must not fail quietly. The pin
# itself is `hook-pin-check`'s question, not this row's.
cache_step(step) if contains(object.get(step, "uses", ""), "Swatinem/rust-cache")

shared_key(step) := key if {
	cache_step(step)
	key := object.get(step, ["with", "shared-key"], "")
	key != ""
}

# `save-if: false` AS A COMPARISON, NEVER AS A TRUTHINESS TEST. The key is absent
# on most steps, Rego reads an absent path as undefined, and `not undefined`
# HOLDS — so a negated spelling would read every step in the tree as read-only.
# Compared against both spellings the YAML boundary can hand over: a bare `false`
# arrives as a boolean, a quoted one as a string, and a reading that accepted
# only the first would refuse a step that is in fact read-only.
reads_only(step) if object.get(step, ["with", "save-if"], null) == false

reads_only(step) if object.get(step, ["with", "save-if"], null) == "false"

# --- pointers -----------------------------------------------------------------
#
# RULE 4's SHAPE. Each of these resolves a `{path, line}` and nothing else: the
# offending key's VALUE never reaches a finding, because a `shared-key` is
# consumer config and a CI log is public.

# NEITHER OF THESE IS A FUNCTION, AND THAT IS CORRECTNESS RATHER THAN STYLE. A
# `pointer(path, line_of(path))` spelling makes the whole refusal undefined
# whenever the line index cannot place the subject — Rego propagates undefined
# through the argument — so a `line_sources` glob that drifted would switch the
# gate off silently. As sets, a pointer that cannot be resolved costs the LINE
# and never the finding: each rule below emits one refusal per placed line, plus
# a path-only arm for the case where none could be placed.
key_line contains [path, number] if {
	some index, line in input.tree.lines[path]
	startswith(trim_space(line), "shared-key:")
	contains(line, "hashFiles")
	number := index + 1
}

job_line contains [path, name, number] if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	some index, line in input.tree.lines[path]
	trim_space(line) == concat("", [name, ":"])
	number := index + 1
}

placed(path) if {
	some placement in key_line
	placement[0] == path
}

job_placed(path, name) if {
	some placement in job_line
	placement[0] == path
	placement[1] == name
}

# --- 1. a key carrying a content hash cannot be read -------------------------

hash_keyed(path) if {
	some entry in job_step
	entry[0] == path
	key := shared_key(entry[2])
	contains(key, "hashFiles")
}

violation contains {
	"rule": "cache-key-carries-a-content-hash",
	"verdict": "step key dead",
	"subjects": [{"path": path, "line": number}],
} if {
	governed
	some path, _ in workflow
	hash_keyed(path)
	some placement in key_line
	placement[0] == path
	number := placement[1]
}

violation contains {
	"rule": "cache-key-carries-a-content-hash",
	"verdict": "step key dead",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in workflow
	hash_keyed(path)
	not placed(path)
}

# --- 2. a pull-request job that reaches cargo declares a cache ---------------
#
# REACHABILITY IS DECIDED FROM THE COMMITTED YAML AND THE COMMITTED MANIFEST,
# with nothing spawned: the job runs `mise run <task>`, and that task's own `run`
# body — or one reached through its `depends` — invokes `cargo`. `mise.toml` is
# the one authority on its own task graph and this reads it as a parsed document
# rather than re-parsing text, for the reason `ci-parity`'s header gives about a
# second authority.

task_run(name) := body if {
	body := object.get(input.tree.documents["mise.toml"].tasks, [name, "run"], "")
	is_string(body)
}

# A task body may be an ARRAY of commands as well as a string, and a reading that
# took only the string form would answer "reaches no cargo" about a task whose
# first line is a `cargo` call — the silent direction.
task_run(name) := body if {
	lines := object.get(input.tree.documents["mise.toml"].tasks, [name, "run"], "")
	is_array(lines)
	body := concat("\n", [line | some line in lines; is_string(line)])
}

# A LIST RATHER THAN AN EDGE SET, because the walk below needs to index it by
# task name and Rego offers no lookup into a set of pairs. The two bodies are the
# two shapes mise accepts: a `depends` naming ONE task arrives as a bare string
# rather than a list, and an array-only reading would miss it entirely — the
# silent direction.
depends_of(name) := deps if {
	declared := object.get(input.tree.documents["mise.toml"].tasks, [name, "depends"], [])
	is_array(declared)
	deps := [dep |
		some entry in declared
		is_string(entry)
		dep := split(trim_space(entry), " ")[0]
	]
}

depends_of(name) := deps if {
	declared := object.get(input.tree.documents["mise.toml"].tasks, [name, "depends"], [])
	is_string(declared)
	declared != ""
	deps := [split(trim_space(declared), " ")[0]]
}

invokes_cargo(name) if contains(task_run(name), "cargo")

# THE CLOSURE IS EXPANDED BY HAND TO A STATED DEPTH, and the reason is the
# evaluator rather than the author's patience: a self-referential rule is not
# expressible in Rego, and `graph.reachable` is not in this build's regorus
# feature set (`Cargo.toml` is the one authority on that list — ast, std, arc,
# coverage, regex). So the walk is written out.
#
# THREE LEVELS, AND THE BOUND IS LOUD RATHER THAN SILENT. Measured over this
# manifest: `test:bats`, `batten-check`, `perf-gate` and `verify` reach cargo at
# depth 0, `ci` and `commit-lint` at depth 1. Three levels is therefore double
# the deepest live chain — and a chain that runs PAST the bound without resolving
# raises `task graph deep` below instead of being read as "reaches no cargo",
# because under-denying here is exactly the dead-gate direction this module
# exists to close.
reaches_cargo(name) if invokes_cargo(name)

reaches_cargo(name) if {
	one := depends_of(name)[_]
	invokes_cargo(one)
}

reaches_cargo(name) if {
	one := depends_of(name)[_]
	two := depends_of(one)[_]
	invokes_cargo(two)
}

reaches_cargo(name) if {
	one := depends_of(name)[_]
	two := depends_of(one)[_]
	three := depends_of(two)[_]
	invokes_cargo(three)
}

# A chain still branching at the bound, with no cargo found along it. Reported
# rather than assumed either way: the module cannot see past its own walk, and
# saying so is the difference between a gate that abstains and one that passes.
unresolved(name) if {
	not reaches_cargo(name)
	one := depends_of(name)[_]
	two := depends_of(one)[_]
	three := depends_of(two)[_]
	count(depends_of(three)) > 0
}

# THE BODY IS BOUND BEFORE THE `regex.*` CALL, and that is a load-time
# requirement rather than a style choice: `collect_inline_regex` recurses into
# EVERY argument of a regex builtin, so a string literal passed as the subject —
# `object.get(entry[2], "run", "")` written in place — is read as an inline
# regex and the module is refused at load, naming `run` as the expression.
job_task contains [path, name, task] if {
	some entry in job_step
	path := entry[0]
	name := entry[1]
	body := object.get(entry[2], "run", "")
	some fragment in regex.find_n(data.batten.patterns["mise-run-task"], body, -1)
	task := split(fragment, " ")[2]
}

declares_a_cache(path, name) if {
	some entry in job_step
	entry[0] == path
	entry[1] == name
	cache_step(entry[2])
}

uncached(path, name, task) if {
	on_pull_request(path)
	[path, name, task] in job_task
	reaches_cargo(task)
	not declares_a_cache(path, name)
}

reach contains [path, name, task] if {
	some entry in job_task
	path := entry[0]
	name := entry[1]
	task := entry[2]
}

violation contains {
	"rule": "cargo-reach-declares-a-cache",
	"verdict": "job declare missing",
	"subjects": [{"path": path, "line": number}, {"artifact": task}],
} if {
	governed
	some entry in reach
	path := entry[0]
	name := entry[1]
	task := entry[2]
	uncached(path, name, task)
	some placement in job_line
	placement[0] == path
	placement[1] == name
	number := placement[2]
}

violation contains {
	"rule": "cargo-reach-declares-a-cache",
	"verdict": "job declare missing",
	"subjects": [{"path": path}, {"artifact": task}],
} if {
	governed
	some entry in reach
	path := entry[0]
	name := entry[1]
	task := entry[2]
	uncached(path, name, task)
	not job_placed(path, name)
}

violation contains {
	"rule": "cargo-reach-declares-a-cache",
	"verdict": "task resolve missing",
	"subjects": [{"path": path}, {"artifact": task}],
} if {
	governed
	some entry in reach
	path := entry[0]
	name := entry[1]
	task := entry[2]
	on_pull_request(path)
	unresolved(task)
	not declares_a_cache(path, name)
}

# --- 3. a pull-request reader of a warmed family does not write to it ---------
#
# A cache entry is IMMUTABLE once written, so on a fresh key the first job to
# finish becomes the entry every later reader inherits — and the pull-request
# jobs reading `ci-` do not build the same amount. `commit-lint` builds one
# binary and finishes roughly eleven minutes before `ci`, which builds the
# workspace and its test targets. A pull-request write is also unreadable by
# every other pull request, so it is upload time for an entry with no reader.
# One designated writer on the trunk, every pull-request consumer read-only.

warmed contains key if {
	some entry in job_step
	on_push(entry[0])
	key := shared_key(entry[2])
}

contested(path, name) if {
	on_pull_request(path)
	some entry in job_step
	entry[0] == path
	entry[1] == name
	step := entry[2]
	shared_key(step) in warmed
	not reads_only(step)
}

violation contains {
	"rule": "warmed-family-is-read-only",
	"verdict": "job write unsafe",
	"subjects": [{"path": path, "line": number}],
} if {
	governed
	some job in job_of
	path := job[0]
	name := job[1]
	contested(path, name)
	some placement in job_line
	placement[0] == path
	placement[1] == name
	number := placement[2]
}

violation contains {
	"rule": "warmed-family-is-read-only",
	"verdict": "job write unsafe",
	"subjects": [{"path": path}],
} if {
	governed
	some job in job_of
	path := job[0]
	name := job[1]
	contested(path, name)
	not job_placed(path, name)
}

# --- could not look ----------------------------------------------------------
#
# A DECLARED SOURCE THAT WOULD NOT PARSE IS NOT AN ABSENT ONE. Absent is
# not-applicable — this tree runs no such workflow — and unparsed means the
# boundary tried and failed. Spelling those the same way is how a gate reports
# green over a file it never read, and a module carrying no `missing` clause
# abstains rather than saying so.

violation contains {
	"rule": "cargo-reach-declares-a-cache",
	"verdict": "workflow read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	endswith(path, ".yml")
}

violation contains {
	"rule": "cargo-reach-declares-a-cache",
	"verdict": "task resolve missing",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	path == "mise.toml"
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicates; it cannot prove the ENGINE builds
# the documents these rules read, which is
# `crates/batten/tests/it/ci_cache_declared.rs`'s whole reason to exist. Both
# measured instances of the dead-key class in this repository were found by
# adding that tier rather than by reading one of these.

test_a_readable_key_with_a_cache_is_clean if {
	count(violation) == 0 with input as tree(warm_writer, pr_reader("ci-", false))
}

test_a_shared_key_carrying_a_content_hash_is_refused if {
	some finding in violation with input as tree(warm_writer, pr_reader("ci-${{ hashFiles('Cargo.toml') }}", false))
	finding.rule == "cache-key-carries-a-content-hash"
}

test_a_cargo_job_with_no_cache_step_is_refused if {
	some finding in violation with input as tree(warm_writer, uncached_reader)
	finding.rule == "cargo-reach-declares-a-cache"
	finding.verdict == "job declare missing"
}

test_a_pull_request_writer_of_a_warmed_family_is_refused if {
	some finding in violation with input as tree(warm_writer, pr_reader("ci-", true))
	finding.rule == "warmed-family-is-read-only"
}

# ANTI-VACUITY, AND IT IS WHAT DISCRIMINATES THE THIRD PREDICATE FROM A BLANKET
# REFUSAL: a family nothing on the trunk writes is not warmed, so a pull-request
# job writing it is this rule's business only once a warm writer exists. Without
# this case the third clause would pass for the wrong reason.
test_an_unwarmed_family_may_still_be_written if {
	count(violation) == 0 with input as tree(no_writer, pr_reader("cross-", true))
}

test_a_job_reaching_no_cargo_needs_no_cache if {
	count(violation) == 0 with input as tree(warm_writer, inert_reader)
}

test_a_cargo_reach_through_depends_is_seen if {
	some finding in violation with input as tree(warm_writer, indirect_reader)
	finding.rule == "cargo-reach-declares-a-cache"
}

test_an_unparsed_workflow_is_could_not_look if {
	some finding in violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {}}, ".github/workflows/w.yml": {"jobs": {}}},
		"lines": {},
		"missing": {".github/workflows/broken.yml": "Unparsed"},
	}}
	finding.verdict == "workflow read unread"
}

# --- fixtures -----------------------------------------------------------------

tasks := {
	"build": {"run": "cargo run --quiet -p batten -- enforce"},
	"lint": {"depends": ["build"]},
	"inert": {"run": "echo nothing"},
}

warm_writer := {"on": {"push": {"branches": ["main"]}}, "jobs": {"cache-warm-linux": {"steps": [{
	"uses": "Swatinem/rust-cache@6323deb1",
	"with": {"shared-key": "ci-"},
}]}}}

no_writer := {"on": {"push": {"branches": ["main"]}}, "jobs": {"noop": {"steps": [{"run": "echo nothing"}]}}}

pr_reader(key, writes) := {"on": {"pull_request": {"types": ["opened"]}}, "jobs": {"reader": {"steps": [
	{"run": "mise run build"},
	{
		"uses": "Swatinem/rust-cache@6323deb1",
		"with": with_save(key, writes),
	},
]}}}

with_save(key, true) := {"shared-key": key}

with_save(key, false) := {"shared-key": key, "save-if": false}

uncached_reader := {"on": {"pull_request": {"types": ["opened"]}}, "jobs": {"reader": {"steps": [{"run": "mise run build"}]}}}

indirect_reader := {"on": {"pull_request": {"types": ["opened"]}}, "jobs": {"reader": {"steps": [{"run": "mise run lint"}]}}}

inert_reader := {"on": {"pull_request": {"types": ["opened"]}}, "jobs": {"reader": {"steps": [{"run": "mise run inert"}]}}}

tree(writer, reader) := {"tree": {
	"documents": {
		"mise.toml": {"tasks": tasks},
		".github/workflows/warm.yml": writer,
		".github/workflows/pr.yml": reader,
	},
	"lines": {".github/workflows/pr.yml": ["jobs:", "  reader:"]},
	"missing": {},
}}
