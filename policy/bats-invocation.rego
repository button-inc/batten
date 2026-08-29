# The pole of the gate keeps its speed-up, its count, and its cost (CLOUD-386).
#
# Successor to `tests/test-bats-parallel.bats`, retired under CLOUD-1059's arm B:
# that suite was an authored bats file, so maintaining it in place was refused and
# the campaign's own route — port the predicate, delete the file, record the
# successor — is what this module is.
#
# WHY THE PREDICATE EXISTS AT ALL. A speed-up is the one kind of fix that rots
# silently. Nothing fails when `--jobs` is dropped in a merge: the suite still
# passes, just slower, and the cost reappears in the lap economics where no gate
# is looking. `timeout-check` cannot see it either — it carries 3x headroom over
# p95, which absorbs a return to serial without a single red build.
#
# THE THREE CLASSES, AND WHY THEY ARE THREE. Each names a different way the pole
# stops being watched, and a reader who sees one finding should not have to guess
# which:
#
#   V-BATS-NOT-PARALLEL     the run is serial, or is about to be
#   V-BATS-RUN-UNCOUNTED    the run proves less than it appears to
#   V-BATS-COST-UNMEASURED  nothing compares what the run cost against a record
#
# The third is CLOUD-386's third measurement (2026-08-28) and is the new half:
# `test:bats` was 1435.7s at 2 workers on CI against a 1249.1s recorded serial
# total for the same corpus, and nothing was red, because a passing exit code says
# nothing about wall clock.
#
# WHAT THIS CLASS GATES IS THE MEASUREMENT, NEVER THE NUMBER, and that boundary is
# the whole of why it is expressible here at all. The corpus is regenerated
# locally, so comparing it against a CI wall clock sets one machine's serial cost
# against another's parallel one — part of what that reads is the runner, and the
# 2026-08-28 sweep found no setting that clears it. A duration is not a property of
# the commit; that the body still TAKES the measurement is, and it is what this
# refuses to lose.
#
# THE BODY IS READ AS A PARSED DOCUMENT, never as lines. `input.tree.documents`
# hands over `[tasks."test:bats"].run` as the string mise itself will execute, so
# no block-boundary scan can drift from what runs. The retired suite awk'd the
# `[tasks."test:bats"]` block out of the manifest, which is the same question
# asked less reliably. Lines are read for exactly one thing the parser cannot see:
# a COMMENT, which is where both measurement dates live.
#
# APPLICABILITY IS THE TASK'S OWN EXISTENCE. A tree with no `test:bats` task is
# not answering for this rule — that is `command-task-defined`'s measured lesson,
# where an unguarded module reported seven findings against a fixture carrying a
# copy of this config and no task namespace. Absent is not-applicable; declared
# and unparsed is could-not-look and stays loud.
#
#MUTANT-EXEMPT CLOUD-931|no `tests/bats-invocation.bats` exists and none may: this row is a retirement under CLOUD-1059, whose whole subject is that the predicate stops living in a bats suite. `mutant` resolves a gate's suite as `tests/$gate.bats`, so there is no named case a mutation could turn red; the second tier is `crates/batten/tests/bats_invocation.rs`, which drives the compiled binary

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.bats_invocation

import rego.v1

rules contains "bats-invocation"

# --- what is being judged, and whether there is anything to judge -------------

manifest := input.tree.documents["mise.toml"]

body := manifest.tasks["test:bats"].run

# The guard, and the whole reason this rule does not fire on a foreign tree: a
# repository with no `test:bats` task has no pole and is answering for nothing.
governed if body

# --- the markers, as data rather than as nine rule bodies ---------------------

# THE SPEED-UP ITSELF. Each is a conjunct of "this run is parallel and stays
# parallel", and each was a case of the retired suite.
parallel_markers := {
	"--jobs",
	"--no-parallelize-within-files",
	"--parallel-binary-name rush",
	"workers=$(nproc)",
	`--jobs "$workers"`,
}

# SERIAL WEARING THE FLAG'S COSTUME. `--jobs 1` is refused by bats itself
# alongside `--no-parallelize-within-files`, measured while re-running the sweep,
# so this arm is belt-and-braces there — but the two capped spellings are not
# refused by anything else, and CLOUD-439 measured what a cap costs: at 2 workers
# on a 4-core box the step went 100.3s -> 210.7s.
serial_spellings := {
	"--jobs 1",
	"-j 1",
	"nproc) /",
	"nproc)/",
}

# THE RUN PROVES WHAT IT RAN. `expected` is computed and compared, both over the
# SAME selected list, and the selector's status is read rather than its output
# (CLOUD-480: a selector that died partway left partial output, and the emptiness
# check passed over it — a narrow run, which has no symptom).
counted_markers := {
	"suites=$(./mise-tasks/suite-select.sh) || suites=\"\"",
	`if [ -z "$suites" ]`,
	`awk '/^@test /{n++} END{print n+0}'`,
	`"$ran" != "$expected"`,
	"of $expected cases reported by the runner",
	"--report-formatter junit",
	"target/bats-report",
}

# THE REPORT SURVIVES THE RUN, or the cost corpus has no source (CLOUD-352). A
# re-added `mktemp` + `trap` leaves `suite-bench` reporting could-not-look
# forever, which is quiet.
discarded_report := {
	"report=$(mktemp",
	"trap 'rm -rf",
}

# WHAT THE RUN COST, AGAINST A RECORD. The comparison is over the suites this run
# SELECTED — selection narrows on purpose, so a whole-corpus total would pass
# every narrowed run vacuously — and a suite the corpus does not record is
# could-not-look rather than either answer.
cost_markers := {
	"started=$(date +%s)",
	"elapsed=$(($(date +%s) - started))",
	"bench/suites/RESULTS.md",
	`[ "$elapsed" -ge "$recorded" ]`,
	`[ "$recorded" = "-" ]`,
	"s wall vs ",
}

# --- A: the run is serial, or is about to be ---------------------------------

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-NOT-PARALLEL",
	"subjects": [{"path": "mise.toml"}, {"artifact": marker}],
} if {
	governed
	some marker in parallel_markers
	not contains(body, marker)
}

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-NOT-PARALLEL",
	"subjects": [{"path": "mise.toml"}, {"artifact": spelling}],
} if {
	governed
	some spelling in serial_spellings
	contains(body, spelling)
}

# ONE AUTHORITY FOR THE NUMBER. The body reports the count it used, and a second
# `$(nproc)` to print it would be a second authority for one number — the shape
# non-negotiable rule 6 refuses, and the exact defect CLOUD-439 went looking for
# elsewhere. Comment lines are excluded because the sweep's own prose names the
# call it is explaining.
nproc_mentions := [line |
	some line in input.tree.lines["mise.toml"]
	contains(line, "nproc")
	not startswith(trim_space(line), "#")
]

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-NOT-PARALLEL",
	"subjects": [{"path": "mise.toml"}, {"count": count(nproc_mentions)}],
} if {
	governed
	count(nproc_mentions) != 1
}

# THE BACKEND IS A PINNED TOOL, so the fast path cannot depend on the host. bats
# defaults to probing for GNU parallel, which is not in the mise registry and is
# pinned nowhere here.
violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-NOT-PARALLEL",
	"subjects": [{"path": "mise.toml"}, {"artifact": "aqua:shenwei356/rush"}],
} if {
	governed
	not manifest.tools["aqua:shenwei356/rush"]
}

# AND CI INSTALLS IT. `ci-tools-check` asserts every name in `install_args`
# resolves to a `[tools]` entry; it cannot assert the converse, that a tool the
# gate NEEDS is in the list. Without this the job provisions no rush and the
# fastest step in the gate is the one that cannot start — bats aborts rather than
# falling back when the named binary is absent.
#
# THE JOB IS DERIVED, NEVER NAMED (CLOUD-1140). This clause read
# `jobs.ci.steps` for its whole life, which was correct exactly while the `ci`
# job was the one running the suite. When the suite moved to its own runner that
# spelling kept asserting about a job that no longer runs it — green, over a
# `bats` job with no rush in its list, which is the same false green this row
# exists to refuse one layer over. So the job is the one whose steps invoke the
# suite, and it follows the suite wherever it goes next.
suite_jobs contains name if {
	some name, job in input.tree.documents[".github/workflows/ci.yml"].jobs
	some step in job.steps
	contains(step.run, "mise run test:bats")
}

ci_install_args := [args |
	some name in suite_jobs
	some step in input.tree.documents[".github/workflows/ci.yml"].jobs[name].steps
	args := step["with"].install_args
]

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-NOT-PARALLEL",
	"subjects": [
		{"path": ".github/workflows/ci.yml"},
		{"artifact": "aqua:shenwei356/rush"},
	],
} if {
	governed
	count(ci_install_args) > 0
	every args in ci_install_args {
		not contains(args, "aqua:shenwei356/rush")
	}
}

# --- B: the run proves less than it appears to -------------------------------

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-RUN-UNCOUNTED",
	"subjects": [{"path": "mise.toml"}, {"artifact": marker}],
} if {
	governed
	some marker in counted_markers
	not contains(body, marker)
}

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-RUN-UNCOUNTED",
	"subjects": [{"path": "mise.toml"}, {"artifact": spelling}],
} if {
	governed
	some spelling in discarded_report
	contains(body, spelling)
}

# --- C: nothing compares what the run cost against a record -------------------

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-COST-UNMEASURED",
	"subjects": [{"path": "mise.toml"}, {"artifact": marker}],
} if {
	governed
	some marker in cost_markers
	not contains(body, marker)
}

# THE SWEEP NAMES ITS HARDWARE AND ITS DATE, which is CLOUD-386's first predicate
# and the defect that produced it: the recorded 4-worker optimum was measured on a
# 4-core box, and the CI runner has 2 — so "4 is the MEASURED optimum" and "do not
# budget this number down" sat in-code as live instructions about hardware CI does
# not have. A table that cannot say what it was taken on cannot be read.
sweep_dates := {date |
	some line in input.tree.lines["mise.toml"]
	contains(line, "# sweep: measured=")
	contains(line, "cores=")
	date := measured_date(line)
}

measured_date(line) := date if {
	parts := split(line, "measured=")
	count(parts) > 1
	date := substring(parts[1], 0, 10)
}

violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-COST-UNMEASURED",
	"subjects": [
		{"path": "mise.toml"},
		{"artifact": "# sweep: measured=<YYYY-MM-DD> cores=<n>"},
	],
} if {
	governed
	count(sweep_dates) == 0
}

# AND THE BUDGET IS RE-MEASURED IN THE SAME PASS, CLOUD-386's third predicate.
# `ci.yml` declared `p95=701s x3 measured=2026-08-14` while the observed job was
# 1212-1674s: stale by 2.4x, with only the x3 multiplier keeping the ceiling from
# firing. Anchored on the newest sweep rather than on a job name, because a
# `# budget:` line's job is YAML context a line scan does not have — and the
# property wanted is exactly this one: move the pole, re-measure the workflow that
# runs it.
#
# MEASURED BUDGETS ONLY. A `grandfathered` row carries no p95 to go stale and is
# CLOUD-352's whole scope; demanding a fresh date for one would be asking for a
# number nobody measured.
violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-COST-UNMEASURED",
	"subjects": [{"path": ".github/workflows/ci.yml", "line": index + 1}],
} if {
	governed
	count(sweep_dates) > 0
	some index, line in input.tree.lines[".github/workflows/ci.yml"]
	contains(line, "# budget: p95=")
	measured_date(line) < max(sweep_dates)
}

# --- could not look ----------------------------------------------------------

# A DECLARED SOURCE THAT WOULD NOT PARSE is not an absent one. Absent is
# not-applicable — this tree has no pole — and unparsed means the boundary tried
# and failed, which must not be spelled the same way as a manifest whose task is
# in order. (CLOUD-1049: the engine half does not populate `missing` for a parse
# failure yet, so this clause is right and the channel is not yet filled.)
violation contains {
	"rule": "bats-invocation",
	"verdict": "V-BATS-SOURCE-UNREAD",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	path == "mise.toml"
}

# --- cases -------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds the
# document these rules read, which is `crates/batten/tests/bats_invocation.rs`'s
# job and the reason that file exists.

sound_body := concat("", [
	`started=$(date +%s)`,
	` bats --parallel-binary-name rush --jobs "$workers" --no-parallelize-within-files`,
	` --report-formatter junit --output "$report" $suites`,
	` elapsed=$(($(date +%s) - started))`,
	` workers=$(nproc)`,
	` suites=$(./mise-tasks/suite-select.sh) || suites=""`,
	` if [ -z "$suites" ]; then :; fi`,
	` awk '/^@test /{n++} END{print n+0}' $suites`,
	` [ "$ran" != "$expected" ]`,
	` of $expected cases reported by the runner`,
	` target/bats-report`,
	` bench/suites/RESULTS.md`,
	` [ "$elapsed" -ge "$recorded" ]`,
	` [ "$recorded" = "-" ]`,
	` echo "${elapsed}s wall vs ${recorded}s recorded serial"`,
])

sound_input(body_text) := {"tree": {
	"documents": {
		"mise.toml": {
			"tasks": {"test:bats": {"run": body_text}},
			"tools": {"aqua:shenwei356/rush": "0.6.0"},
		},
		# The step carries BOTH the invocation and the install list, because the
		# job is now derived from which one runs the suite (CLOUD-1140). A fixture
		# with only the list would make `suite_jobs` empty and the install clause
		# vacuous — a fixture that cannot reach the assertion it exists for.
		".github/workflows/ci.yml": {"jobs": {"bats": {"steps": [{
			"run": "mise run test:bats",
			"with": {"install_args": "rust aqua:shenwei356/rush"},
		}]}}},
	},
	"lines": {
		"mise.toml": [
			"workers=$(nproc)",
			"# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)",
		],
		".github/workflows/ci.yml": ["    timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28"],
	},
	"missing": [],
}}

test_a_sound_invocation_is_clean if {
	found := violation with input as sound_input(sound_body)
	count(found) == 0
}

test_a_dropped_jobs_flag_is_refused if {
	found := violation with input as sound_input(replace(sound_body, `--jobs "$workers"`, ""))
	count(found) > 0
	some finding in found
	finding.verdict == "V-BATS-NOT-PARALLEL"
}

test_a_count_of_one_is_refused_even_though_bats_refuses_it_too if {
	found := violation with input as sound_input(concat("", [sound_body, " --jobs 1"]))
	some finding in found
	finding.verdict == "V-BATS-NOT-PARALLEL"
}

test_a_count_capped_below_the_machine_is_refused if {
	found := violation with input as sound_input(concat("", [sound_body, " workers=$(($(nproc) / 2))"]))
	some finding in found
	finding.verdict == "V-BATS-NOT-PARALLEL"
}

test_a_run_that_counts_nothing_is_refused if {
	found := violation with input as sound_input(replace(sound_body, `[ "$ran" != "$expected" ]`, ""))
	some finding in found
	finding.verdict == "V-BATS-RUN-UNCOUNTED"
}

test_a_discarded_report_is_refused if {
	found := violation with input as sound_input(concat("", [sound_body, " report=$(mktemp -d)"]))
	some finding in found
	finding.verdict == "V-BATS-RUN-UNCOUNTED"
}

test_a_run_that_measures_no_cost_is_refused if {
	found := violation with input as sound_input(replace(sound_body, `[ "$elapsed" -ge "$recorded" ]`, ""))
	some finding in found
	finding.verdict == "V-BATS-COST-UNMEASURED"
}

# THE PREDICATE THAT PRODUCED THIS ROW: a sweep table that does not say what
# hardware it was taken on reads as a live instruction on every machine.
test_a_sweep_without_its_hardware_is_refused if {
	found := violation with input as {"tree": {
		"documents": sound_input(sound_body).tree.documents,
		"lines": {
			"mise.toml": ["workers=$(nproc)"],
			".github/workflows/ci.yml": ["    timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28"],
		},
		"missing": [],
	}}
	some finding in found
	finding.verdict == "V-BATS-COST-UNMEASURED"
}

# AND A BUDGET OLDER THAN THE SWEEP: the pole moved and the workflow that runs it
# was not re-measured in the same pass.
test_a_budget_older_than_the_sweep_is_refused if {
	found := violation with input as {"tree": {
		"documents": sound_input(sound_body).tree.documents,
		"lines": {
			"mise.toml": [
				"workers=$(nproc)",
				"# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)",
			],
			".github/workflows/ci.yml": ["    timeout-minutes: 36 # budget: p95=701s x3 measured=2026-08-14"],
		},
		"missing": [],
	}}
	some finding in found
	finding.verdict == "V-BATS-COST-UNMEASURED"
}

# A GRANDFATHERED ROW IS NOT STALE, it is undeclared, and it is CLOUD-352's.
test_a_grandfathered_budget_is_left_alone if {
	found := violation with input as {"tree": {
		"documents": sound_input(sound_body).tree.documents,
		"lines": {
			"mise.toml": [
				"workers=$(nproc)",
				"# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)",
			],
			".github/workflows/ci.yml": ["    timeout-minutes: 5 # budget: grandfathered measured=2026-08-14"],
		},
		"missing": [],
	}}
	count(found) == 0
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT: a tree with no
# `test:bats` task has no pole to judge. This is `command-task-defined`'s measured
# lesson, where the unguarded form reported seven findings against a fixture.
test_a_tree_with_no_such_task_is_not_this_rules_business if {
	found := violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {"other": {"run": "true"}}}},
		"lines": {"mise.toml": []},
		"missing": [],
	}}
	count(found) == 0
}

# COULD NOT LOOK STAYS LOUD, and is spelled differently from both of the above.
test_an_unreadable_manifest_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"missing": ["mise.toml"],
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "V-BATS-SOURCE-UNREAD"
}
