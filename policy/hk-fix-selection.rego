# `mise run fmt` runs the fixers, and only the fixers (CLOUD-681).
#
# THE DEFECT, MEASURED. `hk.pkl` gave all three hooks the same step list, and hk
# does NOT no-op a step that has no fixer under `fix` — it runs the step's CHECK.
# So `hk fix --all --plan` included 58 steps on this checkout, among them
# `test:bats`, the cargo `test` build, `batten-check`, `policy-test`,
# `sbom-check` and `token-bench-check`. Seven of the 58 declared a fixer.
#
# What that cost is not the runtime alone. Two authorities — the `fmt` task's own
# description and `.claude/rules/toolchain.md` — call it the formatters-only
# subset, and `mem:memory_maintenance` builds advice on top of that reading
# ("edit memories BEFORE `mise run fmt`", offering a formatter as "the cheap fix
# — seconds, against a ~3.5-minute `verify`"). It was `verify`-class work under a
# name that reads as seconds, which is the exact trap that advice exists to help
# a reader avoid. And because the installed git hook refuses to re-enter a gate
# already running, an agent who reached for a format pass mid-task could not
# commit until the whole suite finished.
#
# THE TWO CLASSES, AND WHY THEY ARE TWO. Each is a different way the config and
# the prose stop agreeing, and a reader who sees one finding should not have to
# guess which side moved:
#
#   V-FMT-DESCRIBED-AS-THE-GATE the prose stopped saying formatters-only
#   V-FIXER-TASK-UNROUTED       a fixer task exists that `mise run fmt` cannot reach
#
# The second is the half that would otherwise be invisible, and it is the second
# defect this row was written on. `deno-fmt`'s step carried a `check` and no
# `fix`, while `fmt`'s description named `deno fmt` among the fixers it runs — so
# the description was wrong in BOTH directions at once: `fmt` ran 51 things it
# never promised, and never ran one thing it did. Nothing was red, because a
# fixer nobody routes is indistinguishable from a tree that needs no fixing.
#
# WHAT THIS ROW DELIBERATELY DOES NOT CARRY. The issue's §2 predicate — hk's
# `fix` selection equals the gate's fixer-bearing steps — is NOT here, because it
# is not answerable from lines. It needs the config EVALUATED, and the evaluation
# is exactly where the surprise was: the derived form (`steps = fixers` filtered
# on `step.fix != null`) evaluates correctly under `pkl` and hk's own embedded
# evaluator reads it as EMPTY, so `hk fix --all` reported "no steps to run" and
# formatted nothing, green. `fix-selection-check` is that predicate, as a
# `command` row that asks pkl for the symmetric difference; this row is the half
# that a set comparison cannot see — whether the two DESCRIPTIONS still agree
# with what the config does, and whether a fixer task exists that no step routes.
#
# LINES, NOT A PARSED DOCUMENT, and the reason is a limitation rather than a
# choice: `hk.pkl` is Pkl, which the boundary does not parse into
# `input.tree.documents`. `mise.toml` IS parsed, and class B reads the task
# table there rather than scanning for task names — which is what makes it
# derived from the repository's own fixer set instead of a list restated here.
#
#MUTANT-SUITE crates/batten/tests/it/hk_fix_selection.rs
#MUTANT governance-unread|s@^\tgoverned$@\tfalse@|a_fixer_task_no_step_routes_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.hk_fix_selection

import rego.v1

rules contains "hk-fix-selection"

# --- what is being judged, and whether there is anything to judge -------------

config := input.tree.lines["hk.pkl"]

# The guard, and the whole reason this rule does not fire on a foreign tree: a
# repository with no `hk.pkl` runs no hk hooks and is answering for nothing.
# `command-task-defined`'s measured lesson — an unguarded module reported seven
# findings against a fixture that carried a copy of this config and none of its
# subjects.
governed if count(config) > 0

# Does any line of the config carry this text? Substring rather than a regex,
# which is what keeps this module free of an inline pattern (`[[pattern]]` is the
# registry, and a literal is not a pattern).
declares(marker) if {
	some line in config
	contains(line, marker)
}

# --- A: the prose stopped saying formatters-only ------------------------------

# The inverse direction the issue names. Exactly one of the two sides was allowed
# to move, and `hk.pkl` is the one that did; if a later change instead widens
# `fmt` back to the gate, these two sentences are what must be corrected in the
# same commit rather than left describing something else.
#
# The task description comes from the PARSED manifest — it is the string mise
# itself prints for `mise tasks info fmt`, so no block scan can drift from what a
# reader is actually shown.
fmt_description := input.tree.documents["mise.toml"].tasks.fmt.description

violation contains {
	"rule": "hk-fix-selection",
	"verdict": "V-FMT-DESCRIBED-AS-THE-GATE",
	"subjects": [{"path": "mise.toml"}, {"artifact": "Run every fixer over the tree"}],
} if {
	governed
	fmt_description
	not contains(fmt_description, "Run every fixer over the tree")
}

violation contains {
	"rule": "hk-fix-selection",
	"verdict": "V-FMT-DESCRIBED-AS-THE-GATE",
	"subjects": [
		{"path": ".claude/rules/toolchain.md"},
		{"artifact": "`fmt` remains the formatters-only subset"},
	],
} if {
	governed
	rules_lines := input.tree.lines[".claude/rules/toolchain.md"]
	every line in rules_lines {
		not contains(line, "`fmt` remains the formatters-only subset")
	}
}

# --- B: a fixer task exists that `mise run fmt` cannot reach -------------------

# DERIVED FROM THE MANIFEST'S OWN TASK TABLE, never a list of tool names written
# here. Every `fmt:<suffix>` task in `mise.toml` is by construction a fixer half
# somebody wrote; if no hk step routes to it, `mise run fmt` does not run it and
# nothing anywhere says so. That is exactly what happened to `deno fmt`, which
# `fmt`'s description named for its whole life while no step carried the arm.
#
# The check side is deliberately NOT asserted symmetrically: a `lint:<suffix>`
# with no fixer is the ordinary case (a linter that cannot fix), and demanding
# one would be asking for tasks nobody needs.
fixer_tasks := {name |
	some name, _ in input.tree.documents["mise.toml"].tasks
	startswith(name, "fmt:")
}

violation contains {
	"rule": "hk-fix-selection",
	"verdict": "V-FIXER-TASK-UNROUTED",
	"subjects": [{"path": "hk.pkl"}, {"artifact": task}],
} if {
	governed
	some task in fixer_tasks
	not declares(sprintf(`fix = "mise run %s"`, [task]))
}

# --- could not look -----------------------------------------------------------

# A DECLARED SOURCE THAT WOULD NOT PARSE is not an absent one. Absent is
# not-applicable — this tree runs no hk gate — and unparsed means the boundary
# tried and failed, which must not be spelled the same way as a config in order.
# (CLOUD-1049: the engine half does not populate `missing` for a parse failure
# yet, so this clause is right and the channel is not yet filled.)
violation contains {
	"rule": "hk-fix-selection",
	"verdict": "V-HK-SOURCE-UNREAD",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	path in {"hk.pkl", "mise.toml"}
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# the document these rules read, which is `crates/batten/tests/hk_fix_selection.rs`'s
# job and the reason that file exists.

sound_config := [
	"local gate = new Mapping<String, Step> {",
	`  ["deno-fmt"] { check = "mise run lint:deno"; fix = "mise run fmt:deno" }`,
	`  ["rego"] { check = "mise run lint:rego"; fix = "mise run fmt:rego" }`,
	`  ["test:bats"] { check = "mise run test:bats" }`,
	"}",
	"local fixers = new Mapping<String, Step> {",
	`  ["deno-fmt"] = gate["deno-fmt"]`,
	`  ["rego"] = gate["rego"]`,
	"}",
	`  ["fix"] {`,
	"    fix = true",
	"    steps = fixers",
	"  }",
]

sound_input(config_lines) := {"tree": {
	"documents": {"mise.toml": {"tasks": {
		"fmt": {"description": "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list"},
		"fmt:rego": {"run": "opa fmt -w"},
		"fmt:deno": {"run": "deno fmt"},
	}}},
	"lines": {
		"hk.pkl": config_lines,
		".claude/rules/toolchain.md": ["`fmt` remains the formatters-only subset."],
	},
	"missing": [],
}}

test_a_config_and_prose_that_agree_are_clean if {
	found := violation with input as sound_input(sound_config)
	count(found) == 0
}

# THE PROSE DIRECTION. `fix-selection-check` decides what the config DOES; these
# two decide whether what it says still matches. Both authorities are asserted,
# so either one going is a finding.
test_a_task_description_that_names_the_gate_is_refused if {
	sound := sound_input(sound_config)
	found := violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {
			"fmt": {"description": "Run the whole hk gate over the tree"},
			"fmt:rego": {"run": "opa fmt -w"},
			"fmt:deno": {"run": "deno fmt"},
		}}},
		"lines": sound.tree.lines,
		"missing": [],
	}}
	some finding in found
	finding.verdict == "V-FMT-DESCRIBED-AS-THE-GATE"
}

test_a_rules_file_that_dropped_the_clause_is_refused if {
	sound := sound_input(sound_config)
	found := violation with input as {"tree": {
		"documents": sound.tree.documents,
		"lines": {
			"hk.pkl": sound_config,
			".claude/rules/toolchain.md": ["`fmt` runs the whole gate."],
		},
		"missing": [],
	}}
	some finding in found
	finding.verdict == "V-FMT-DESCRIBED-AS-THE-GATE"
}

# THE SECOND DEFECT THIS ROW WAS WRITTEN ON, in the shape it actually had: a
# `fmt:deno` task existed to be written and no step routed `mise run fmt` to it,
# so the formatter the description promised was the one it could not perform.
test_a_fixer_task_no_step_routes_is_refused if {
	unrouted := [line |
		some raw in sound_config
		line := replace(raw, `; fix = "mise run fmt:deno"`, "")
	]
	found := violation with input as sound_input(unrouted)
	some finding in found
	finding.verdict == "V-FIXER-TASK-UNROUTED"
	some subject in finding.subjects
	subject.artifact == "fmt:deno"
}

# NOT-APPLICABLE, NEVER A VACUOUS PASS PRETENDING TO BE A VERDICT: a tree with no
# hk config runs no hk hooks and has nothing here to answer for.
test_a_tree_with_no_hk_config_is_not_this_rules_business if {
	found := violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {"fmt:deno": {"run": "deno fmt"}}}},
		"lines": {"hk.pkl": []},
		"missing": [],
	}}
	count(found) == 0
}

# COULD NOT LOOK STAYS LOUD, and is spelled differently from both of the above.
test_an_unreadable_config_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"missing": ["hk.pkl"],
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "V-HK-SOURCE-UNREAD"
}
