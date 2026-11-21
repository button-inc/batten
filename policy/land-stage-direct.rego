#MUTANT-SUITE crates/batten/tests/it/land_stage_direct.rs
#MUTANT enforce-unread|s@^\tprogram.subcommand == "enforce"$@\tfalse@|every_spelling_of_enforce_is_refused
#MUTANT task-reach-unread|s@^\tis_array(input.call\["task-programs"\])$@\tfalse@|every_spelling_of_a_stage_task_is_refused
#MUTANT background-unread|s@^backgrounded if input.call\["run-in-background"\] == true$@backgrounded if false@|a_backgrounded_land_is_allowed
#MUTANT filter-unread|s@^\tnot filtered(program)$@\ttrue@|the_development_forms_stay_allowed
#MUTANT suite-unread|s@^\tsuite(program)$@\tfalse@|an_unfiltered_suite_is_refused
#MUTANT step-set-unread|s@^\tsome step in input.call\["step-programs"\]$@\tsome step in []@|a_receipted_steps_program_run_outside_it_is_refused
#MUTANT receipt-unexempt|s@^\tnot receipted(program)$@\ttrue@|the_development_forms_stay_allowed
#MUTANT selection-unread|s@^\tselected(program) == selected(step)$@\ttrue@|the_development_forms_stay_allowed
# A land or verify stage, rerun by hand outside the lap that owns it.
#
# MEASURED 2026-11-15, and the incident is the whole reason this exists: an agent
# ran `mise exec -- cargo run -p batten -- enforce --half live` by hand to see
# whether admissions had cleared. `land` runs that exact stage on every lap, the
# live half is unreceipted by design (perf(enforce), 0c026130), so the run kept
# nothing — it duplicated a lap's work and left no record a lap could reuse.
#
# THE TWO KINDS OF RUN ARE TEST SELECTION AND TEST RE-EXECUTION, and the line
# between them is the literature's rather than this repository's. A receipted
# step is a regression-test-selection cache in Ekstazi's sense (Gligoric, Eloussi
# and Marinov, ISSTA 2015): same inputs, same verdict, so a hit answers without
# re-running. A stage run OUTSIDE the step that receipts it is re-execution the
# cache never sees — its verdict is computed and thrown away, and the lap pays
# again. A filtered run is selection by the developer and is the opposite case:
# it answers a narrower question than the stage, so it duplicates nothing.
#
# WHAT A STAGE IS, AND WHY THERE IS NO LIST OF TASK NAMES HERE. A stage is named
# by the PROGRAM it runs, never by the task that wraps it:
#
#   * `batten enforce`, any half — the policy stage `verify` and `land` run;
#   * `batten land verify`, and `batten land lap` in the foreground — the lap
#     itself, which is sanctioned only as the backgrounded `mise run land`;
#   * an unfiltered workspace test run — `cargo test` / `cargo nextest run` with
#     no filterset and no test-name operand, the body of the receipted
#     `test:cargo` step run around its receipt.
#
# Which TASKS are stages is then derived, not declared: `input.call
# ["task-programs"]` is every program the call's tasks reach, followed through
# the task receipt's bodies — `mise run verify` reaches `verify:gated`, which
# reaches `batten-check`, which runs `batten enforce` — so a stage task added or
# renamed tomorrow is refused with no edit here, and a task that does not reach
# a stage program is not refused for its name. A list of names was the
# alternative, and it is wrong on the commit that adds the next stage.
#
# EVERY SPELLING IS THE ENGINE'S, NOT THIS MODULE'S. Shell command analysis
# belongs on a parsed AST, never on a regex over the line — the position of
# ShellCheck (Holen), of Smoosh's executable POSIX semantics (Greenberg and
# Blatt, POPL 2020) and of NL2Bash's corpus work (Lin et al., LREC 2018), which
# all start from the parse. `input.call.programs` is that parse read once
# (CLOUD-1028, CLOUD-1382), and since step 14 it reaches through a shell's `-c`
# script, `eval`, `exec`, the binary `cargo run -p X` starts and the argv
# `batten step run` executes, recursively, for every module. This module reads
# `name`, `subcommand` and `nested` and parses nothing: "which batten verb" and
# "which mise task" are each answered once, in `hook.rs`.
#
# FAIL-CLOSED IN TWO PLACES. A shell script the parser refuses is still run by
# the shell, so the engine reads it by whitespace (`unread`) and this module
# judges that reading like any other. And a FOREGROUND mise task run while the
# task receipt could not be read is refused: what it reaches is unknown, and a
# foreground mise call is against the background-the-slow-path doctrine anyway.
# A top-level line that does not parse at all is `input.call.segments == null`;
# that one is refused when any word of the line names a stage verb, the one place
# this module reads text, because there is no parse to read.
#
# WHAT THIS DOES NOT CLOSE, named. A backgrounded `mise run verify` while the
# task receipt is unreadable reaches nothing this can see. The engine resolves a
# `cargo run` naming no `-p`/`--bin` through the manifest's default-run and
# members, and renders `{{vars.*}}` in task bodies when the receipt is minted;
# a template naming an environment variable unset at session start keeps its
# default, which is what the runner would run then too.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.land_stage_direct

import rego.v1

rules contains "gate run twice"

violation contains {
	"rule": "gate run twice",
	"verdict": "gate run twice",
	"subjects": [{"artifact": program.name}],
} if {
	some program in reached
	stage(program)
}

# THE RECEIPT COULD NOT BE READ, and a foreground call starts a task anyway.
violation contains {
	"rule": "gate run twice",
	"verdict": "gate run twice",
	"subjects": [{"artifact": "mise"}],
} if {
	not is_array(input.call["task-programs"])
	some program in input.call.programs
	program.name == "mise"
	is_array(program.tasks)
	count(program.tasks) > 0
	not backgrounded
}

# NO PARSE AT ALL: the one text read, and only for the stage verbs.
violation contains {
	"rule": "gate run twice",
	"verdict": "gate run twice",
	"subjects": [{"count": 1}],
} if {
	not is_array(input.call.segments)
	some word in split(input.call.command, " ")
	word in {"enforce", "nextest"}
}

# A call the host runs in the background. Absent, `null` and `false` are all
# not backgrounded: only an explicit `true` is the sanctioned lap.
backgrounded if input.call["run-in-background"] == true

# What the call runs: what it wrote, and what the tasks it starts run.
reached contains program if {
	some program in input.call.programs
}

# `null` where the receipt could not be read, and a null collection RAISES in
# `some … in`, so the type is checked first.
reached contains program if {
	is_array(input.call["task-programs"])
	some program in input.call["task-programs"]
}

stage(program) if {
	program.name == "batten"
	program.subcommand == "enforce"
}

stage(program) if {
	program.name == "batten"
	program.subcommand == "land"
	program.nested == "verify"
}

# The lap itself, which is sanctioned exactly once: backgrounded.
stage(program) if {
	program.name == "batten"
	program.subcommand == "land"
	program.nested == "lap"
	not backgrounded
}

stage(program) if {
	suite(program)
	not filtered(program)
}

# A STAGE IS WHAT A STEP RECEIPTS (step 21). Every `[[step]]` a land runs is a
# `batten step run <id> -- <argv>` in a task body, so the engine hands the set
# of those argvs over as `step-programs`, derived from the manifest: a step
# added to a task is a stage on the commit that adds it, with no name listed
# here. Measured on #1276: `cargo clippy -p batten --all-targets -- -D
# warnings`, run three times as a pre-check before `mise run land`, raised
# nothing, because the three program shapes above did not include it, while
# `lint:clippy` receipts exactly that program and the lap then ran it again.
#
# RECEIPTED IS NOT A RERUN. The same program run THROUGH its step writes the
# receipt the lap then hits (`receipted`, set on everything a `step run`
# reaches, the batten a `cargo run` starts inside it included), so that run is
# never wasted; only a run outside any step is re-execution with nothing kept.
#
# A TEST SUITE IS NOT JUDGED HERE: selection by filter is the suite rule's, and
# a filtered run of the program a narrow step receipts stays development.
stage(program) if {
	not receipted(program)
	not suite(program)
	is_array(input.call["step-programs"])
	some step in input.call["step-programs"]
	same_stage(program, step)
}

receipted(program) if program.receipted == true

# batten's verbs are tabled, so its verb and nested verb are its identity.
same_stage(program, step) if {
	program.name == "batten"
	step.name == "batten"
	program.subcommand == step.subcommand
	program.nested == step.nested
}

# ANY OTHER PROGRAM IS ITS VERB AND WHAT IT BUILDS FOR. Cargo identifies a unit
# by package, target triple and profile (its fingerprint key), and a step's
# triples and profile are what separate it from development: `cargo check` on
# the host is not `cross-check`, while every `cargo clippy` is `lint:clippy`.
# The nested word is not compared: past a cargo subcommand it is whatever bare
# word comes first (`-p batten`'s value, `-D warnings`), never a verb.
same_stage(program, step) if {
	program.name != "batten"
	program.name != "mise"
	program.name == step.name
	program.subcommand == step.subcommand
	selected(program) == selected(step)
}

# A MISE RUN IS THE TASKS IT RUNS (CLOUD-2788). Its verb is always `run`, so the
# clause above would make every `mise run <task>` the stage a receipted
# `step run ci-suite -- mise run ci` names; the task list is the identity, the
# same answer `task-programs` reads, and a different task is development.
same_stage(program, step) if {
	program.name == "mise"
	step.name == "mise"
	program.subcommand == step.subcommand
	is_array(program.tasks)
	program.tasks == step.tasks
}

# The `--target` and `--profile` values a program names, each with its option.
selected(program) := {pick |
	some at, word in program.arguments
	some option in {"--target", "--profile"}
	pick := choice(program.arguments, at, word, option)
}

choice(words, at, word, option) := concat("=", [option, words[at + 1]]) if {
	word == option
	at + 1 < count(words)
}

choice(_, _, word, option) := word if {
	startswith(word, concat("", [option, "="]))
}

# A workspace test run: `cargo test`, `cargo nextest run`.
suite(program) if {
	program.name == "cargo"
	program.subcommand in {"test", "t"}
}

suite(program) if {
	program.name == "cargo"
	program.subcommand == "nextest"
	program.nested in {"run", "r"}
}

# What follows the verb: past `test`, or past `nextest … run`.
tail(program) := rest if {
	program.subcommand in {"test", "t"}
	at := count(program["global-options"]) + 1
	rest := array.slice(program.arguments, at, count(program.arguments))
}

tail(program) := rest if {
	program.subcommand == "nextest"
	after := array.slice(program.arguments, count(program["global-options"]) + 1, count(program.arguments))
	some at, word in after
	word == program.nested
	not earlier_verb(after, at, program.nested)
	rest := array.slice(after, at + 1, count(after))
}

earlier_verb(words, at, verb) if {
	some before, word in words
	before < at
	word == verb
}

# ONE `--test <target>` names a single test target, which is selection rather
# than the suite; two, or `--tests`, select every target again.
filtered(program) if {
	words := tail(program)
	count([at | some at, _ in words; single_target(words, at)]) == 1
	not "--tests" in words
}

single_target(words, at) if {
	words[at] == "--test"
	at + 1 < count(words)
}

single_target(words, at) if {
	startswith(words[at], "--test=")
}

# A filterset, a test-name operand, or test-binary arguments after `--`: each
# narrows the run below the stage, which is selection rather than a rerun.
filtered(program) if {
	some word in tail(program)
	word in {"-E", "--filterset", "--filter-expr"}
}

filtered(program) if {
	some word in tail(program)
	some prefix in {"-E", "--filterset=", "--filter-expr="}
	startswith(word, prefix)
	word != prefix
}

filtered(program) if {
	words := tail(program)
	some at, word in words
	not startswith(word, "-")
	not valued(words, at)
	not after_separator(words, at)
}

filtered(program) if {
	words := tail(program)
	some at, word in words
	after_separator(words, at)
	not startswith(word, "-")
}

after_separator(words, at) if {
	some before, word in words
	before < at
	word == "--"
}

# The word at `at` is the value of the option before it.
valued(words, at) if {
	at > 0
	words[at - 1] in value_options
}

# cargo's and nextest's options whose value is the next word. A word missing
# here reads its value as a test-name operand, which ALLOWS — so the list leans
# long, and the cost of a gap is one unrefused rerun, never a refused filter.
value_options := {
	"-p", "--package", "--exclude", "--bin", "--example", "--test", "--bench",
	"-F", "--features", "--profile", "--cargo-profile", "-P", "--target",
	"--target-dir", "--manifest-path", "-j", "--jobs", "--test-threads",
	"--color", "--message-format", "--config", "-Z", "--partition", "--retries",
	"--run-ignored", "--status-level", "--final-status-level", "--failure-output",
	"--success-output", "--max-fail", "--tool-config-file", "--archive-file",
	"--workspace-remap", "--lockfile-path", "--cargo-message-format",
	"--cargo-quiet", "--show-progress", "--no-tests", "--hide-progress-bar",
}

# The load-time tier. These cases hand the predicate the resolution the ENGINE
# produces, so they cannot say whether it does — `land_stage_direct.rs`, over
# the compiled binary, drives every spelling through the engine and is the tier
# `#MUTANT-SUITE` names. At least one case is compound (CLOUD-857).

test_enforce_through_cargo_run_is_refused if {
	some _ in violation with input as {"call": {
		"command": "mise exec -- cargo run -p batten -- enforce --half live",
		"segments": [],
		"programs": [
			{"program": "cargo", "name": "cargo", "arguments": ["run", "-p", "batten", "--", "enforce", "--half", "live"], "subcommand": "run", "global-options": [], "mediated": true},
			{"program": "batten", "name": "batten", "arguments": ["enforce", "--half", "live"], "subcommand": "enforce", "global-options": [], "nested": null, "via": "cargo run", "mediated": true},
		],
		"task-programs": [],
	}}
}

test_a_stage_reached_through_a_task_is_refused if {
	some _ in violation with input as {"call": {
		"command": "cd /tmp && mise run verify",
		"segments": [],
		"run-in-background": true,
		"programs": [
			{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false},
			{"program": "mise", "name": "mise", "arguments": ["run", "verify"], "subcommand": "run", "tasks": ["verify"], "mediated": false},
		],
		"task-programs": [{"program": "batten", "name": "batten", "arguments": ["enforce"], "subcommand": "enforce", "task": "batten-check", "mediated": true}],
	}}
}

test_a_backgrounded_lap_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "mise run land",
		"segments": [],
		"run-in-background": true,
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "land"], "subcommand": "run", "tasks": ["land"], "mediated": false}],
		"task-programs": [{"program": "batten", "name": "batten", "arguments": ["land", "lap"], "subcommand": "land", "nested": "lap", "task": "land", "mediated": true}],
	}}
}

test_a_foreground_lap_is_refused if {
	some _ in violation with input as {"call": {
		"command": "mise run land",
		"segments": [],
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "land"], "subcommand": "run", "tasks": ["land"], "mediated": false}],
		"task-programs": [{"program": "batten", "name": "batten", "arguments": ["land", "lap"], "subcommand": "land", "nested": "lap", "task": "land", "mediated": true}],
	}}
}

test_an_unfiltered_suite_is_refused if {
	some _ in violation with input as {"call": {
		"command": "cargo nextest run --workspace",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["nextest", "run", "--workspace"], "subcommand": "nextest", "nested": "run", "global-options": [], "mediated": false}],
		"task-programs": [],
	}}
}

test_a_filtered_suite_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "cargo nextest run -p batten forced_push",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["nextest", "run", "-p", "batten", "forced_push"], "subcommand": "nextest", "nested": "run", "global-options": [], "mediated": false}],
		"task-programs": [],
	}}
}

test_a_package_alone_is_not_a_filter if {
	some _ in violation with input as {"call": {
		"command": "cargo test -p batten",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["test", "-p", "batten"], "subcommand": "test", "nested": null, "global-options": [], "mediated": false}],
		"task-programs": [],
	}}
}

test_another_batten_verb_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "batten check --rule x",
		"segments": [],
		"programs": [{"program": "batten", "name": "batten", "arguments": ["check", "--rule", "x"], "subcommand": "check", "nested": null, "global-options": [], "mediated": false}],
		"task-programs": [],
	}}
}

test_a_steps_program_outside_its_step_is_refused if {
	some _ in violation with input as {"call": {
		"command": "mise exec -- cargo clippy -q -p batten --all-targets -- -D warnings",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["clippy", "-q", "-p", "batten", "--all-targets", "--", "-D", "warnings"], "subcommand": "clippy", "nested": "batten", "global-options": [], "via": null, "mediated": false}],
		"task-programs": [],
		"step-programs": [{"program": "cargo", "name": "cargo", "arguments": ["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"], "subcommand": "clippy", "nested": "-D", "global-options": [], "via": "step run", "receipted": true, "task": "lint:clippy", "mediated": true}],
	}}
}

test_a_steps_program_through_its_step_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "batten step run lint:clippy -- cargo clippy --all-targets",
		"segments": [],
		"programs": [
			{"program": "batten", "name": "batten", "arguments": ["step", "run", "lint:clippy", "--", "cargo", "clippy", "--all-targets"], "subcommand": "step", "nested": "run", "global-options": [], "via": null, "mediated": false},
			{"program": "cargo", "name": "cargo", "arguments": ["clippy", "--all-targets"], "subcommand": "clippy", "nested": null, "global-options": [], "via": "step run", "receipted": true, "mediated": true},
		],
		"task-programs": [],
		"step-programs": [{"program": "cargo", "name": "cargo", "arguments": ["clippy", "--all-targets"], "subcommand": "clippy", "nested": null, "global-options": [], "via": "step run", "receipted": true, "task": "lint:clippy", "mediated": true}],
	}}
}

test_another_target_is_not_the_step if {
	count(violation) == 0 with input as {"call": {
		"command": "cargo check --all-targets",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["check", "--all-targets"], "subcommand": "check", "nested": null, "global-options": [], "via": null, "mediated": false}],
		"task-programs": [],
		"step-programs": [{"program": "cargo", "name": "cargo", "arguments": ["check", "--target", "x86_64-pc-windows-gnu", "--target=x86_64-unknown-linux-musl"], "subcommand": "check", "nested": null, "global-options": [], "via": "step run", "receipted": true, "task": "cross-check", "mediated": true}],
	}}
}

test_the_steps_targets_are_the_step if {
	some _ in violation with input as {"call": {
		"command": "cargo check --target=x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl",
		"segments": [],
		"programs": [{"program": "cargo", "name": "cargo", "arguments": ["check", "--target=x86_64-pc-windows-gnu", "--target", "x86_64-unknown-linux-musl"], "subcommand": "check", "nested": null, "global-options": [], "via": null, "mediated": false}],
		"task-programs": [],
		"step-programs": [{"program": "cargo", "name": "cargo", "arguments": ["check", "--target", "x86_64-pc-windows-gnu", "--target=x86_64-unknown-linux-musl"], "subcommand": "check", "nested": null, "global-options": [], "via": "step run", "receipted": true, "task": "cross-check", "mediated": true}],
	}}
}

test_another_mise_task_is_not_the_suite_step if {
	count(violation) == 0 with input as {"call": {
		"command": "mise run lint:clippy",
		"segments": [],
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "lint:clippy"], "subcommand": "run", "tasks": ["lint:clippy"], "nested": "lint:clippy", "global-options": [], "via": null, "mediated": false}],
		"task-programs": [],
		"step-programs": [{"program": "mise", "name": "mise", "arguments": ["run", "ci"], "subcommand": "run", "tasks": ["ci"], "nested": "ci", "global-options": [], "via": "step run", "receipted": true, "task": "verify:gated", "mediated": true}],
	}}
}

test_the_suite_steps_task_outside_it_is_refused if {
	some _ in violation with input as {"call": {
		"command": "mise run ci",
		"segments": [],
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "ci"], "subcommand": "run", "tasks": ["ci"], "nested": "ci", "global-options": [], "via": null, "mediated": false}],
		"task-programs": [],
		"step-programs": [{"program": "mise", "name": "mise", "arguments": ["run", "ci"], "subcommand": "run", "tasks": ["ci"], "nested": "ci", "global-options": [], "via": "step run", "receipted": true, "task": "verify:gated", "mediated": true}],
	}}
}

test_a_file_named_enforce_is_not_a_stage if {
	count(violation) == 0 with input as {"call": {
		"command": "cat enforce",
		"segments": [],
		"programs": [{"program": "cat", "name": "cat", "arguments": ["enforce"], "mediated": false}],
		"task-programs": [],
	}}
}

test_a_foreground_task_run_with_no_receipt_is_refused if {
	some _ in violation with input as {"call": {
		"command": "mise run lint",
		"segments": [],
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "lint"], "subcommand": "run", "tasks": ["lint"], "mediated": false}],
		"task-programs": null,
	}}
}

test_an_unparseable_line_naming_a_stage_is_refused if {
	some _ in violation with input as {"call": {
		"command": "batten enforce \"unterminated",
		"segments": null,
		"programs": [],
		"task-programs": [],
	}}
}

deny contains message if {
	some v in violation
	message := v.verdict
}
