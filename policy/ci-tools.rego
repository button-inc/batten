# METADATA
# description: |
#   The per-job install lists name real declared tools, every pull-request
#   workflow carries a BINDING one, and every tool a policy row spawns is on the
#   list — CLOUD-180, CLOUD-812 and CLOUD-480, ported from
#   `mise-tasks/ci-tools-check.sh` under CLOUD-843.
#
#   CI installs a NARROW tool set per job, which is the largest single speed-up
#   available here: every job used to install the whole toolchain, and one tool at
#   17.3s set the wall clock in three jobs that never invoke it.
#
#   The cost of narrowing is a SECOND place where tool names are written down, and
#   the failure mode is drift: rename or re-pin a tool in the manifest and the
#   install list silently keeps the old name. The installer does NOT fail on an
#   unknown tool name, so the drift surfaces much later as "command not found" in
#   whichever step happened to need it — a missing TOOL wearing a missing-STEP
#   costume, which is the same class of late, misattributed failure the diagnostic
#   verb exists to kill.
#
#   THE SECOND DIRECTION, AND WHY THE FIRST COULD NOT ASK IT (CLOUD-812). Judging
#   the names IN a list means a workflow declaring no list has no names to judge,
#   so it passes — and that is not a hole in the predicate, it is a hole in the
#   TRIGGER: the retiring gate was pointed at one file that happened to be
#   compliant. Measured: two other workflows had never been in scope and were still
#   installing every declared tool on every push, to run a subject regex and one
#   analyzer. Nothing was red. Nothing could be. So the question is asked the other
#   way over every workflow that spends a runner on a pull request.
#
#   A LIST WITHOUT THE AUTO-INSTALL VARIABLES IS DECORATIVE: the runner re-installs
#   the missing tools at task time, which is the failure CLOUD-180 measured — one
#   job installing a single tool in 13s and then rebuilding the whole toolchain
#   inside the work step — and which is indistinguishable from a fix by reading the
#   workflow. The ASSIGNMENT is matched, not a mention: a substring search would
#   pass a workflow whose only occurrence is the comment explaining why the
#   variable matters, and would pass one setting it true, which is the same hole
#   wearing a fix's clothing.
#
#   THE THIRD DIRECTION COST TWO CI RUNS (CLOUD-480). Neither direction above can
#   see a tool a POLICY ROW spawns. Two rows ran declared tools that no install
#   list named; with auto-install off making the list binding, they did not run
#   slowly — they failed CLOSED, at deny, while passing locally where the tools are
#   installed. The landing loop refuses that as a verify/CI disagreement and is
#   right to, but nothing named the cause.
#
#   SCOPED TO WHAT THE MANIFEST OWNS, derived rather than allowlisted. A spawned
#   binary can arrive three other ways — bundled with a bigger tool, pre-installed
#   on the runner, or vendored — and all three came back as findings on the first
#   run of that block. Rather than carry a second list of exemptions, the drifting
#   authority this exists to refuse, the question narrows to tools the manifest
#   DECLARES: if it owns the tool, the install list must name it; if it does not,
#   the installer was never going to install it anyway.
#
#   BASENAME MATCHING ON BOTH SIDES, deliberately: the manifest and the list hold
#   backend-qualified keys and a spawn names a binary, so the comparison is over
#   the last path component. Approximate in the SAFE direction — it can fail to
#   catch a mismatch, never invent one — and the precise mapping is the installer's
#   business rather than something restated here.
#
#   SCHEDULED WORKFLOWS ARE OUT OF SCOPE deliberately: they are not on the
#   pull-request path, and widening to them would be a different decision with a
#   different cost argument.
#
#   POINTER, NEVER PAYLOAD (rule 4): the tool name and the file it is missing from.
#   Never the tool set, never a log line.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_tools

import rego.v1

manifest_path := "mise.toml"

policy_path := "batten.toml"

rules contains "ci-tools"

manifest_lines := lines if {
	lines := input.tree.lines[manifest_path]
}

workflow_paths contains path if {
	some path, _ in input.tree.lines
	startswith(path, ".github/workflows/")
}

basename(name) := parts[count(parts) - 1] if {
	parts := split(replace(name, ":", "/"), "/")
}

# --- what the manifest declares ----------------------------------------------

tools_start := i if {
	some i, line in manifest_lines
	startswith(line, "[tools]")
}

tools_end := e if {
	after := {j |
		some j, line in manifest_lines
		j > tools_start
		startswith(line, "[")
	}
	e := min(after)
}

tools_end := count(manifest_lines) if {
	tools_start
	not another_table_after_tools
}

another_table_after_tools if {
	some j, line in manifest_lines
	j > tools_start
	startswith(line, "[")
}

declared contains key if {
	some j, line in manifest_lines
	j > tools_start
	j < tools_end
	not startswith(trim_space(line), "#")
	contains(line, "=")
	key := replace(trim_space(substring(line, 0, indexof(line, "="))), "\"", "")
	key != ""
}

owned contains basename(key) if {
	some key in declared
}

# --- what a workflow asks to install -----------------------------------------
#
# Each list is a one-line plain scalar, which the workflows state and this relies
# on: a block scalar would need continuation tracking, and several tool names
# carry a backend prefix so they read as new keys under any such heuristic.
requested contains {"path": path, "line": i + 1, "tool": tool} if {
	some path in workflow_paths
	some i, line in input.tree.lines[path]
	regex.match(data.batten.patterns["install-args-line"], line)
	rest := substring(line, indexof(line, ":") + 1, -1)
	some raw in split(trim_space(rest), " ")
	tool := trim_space(raw)
	tool != ""
}

# --- direction 1: every name resolves ----------------------------------------

violation contains {
	"rule": "ci-tools",
	"verdict": "tool name unknown",
	"subjects": [{"artifact": sprintf("%s:%d %s", [row.path, row.line, row.tool])}],
} if {
	count(declared) > 0
	some row in requested
	not row.tool in declared
}

# THE VACUITY ARMS. A manifest declaring no tools cannot answer the question, and
# a tree whose workflows request nothing is one where every job installs the whole
# toolchain — the state the narrowing removed.
violation contains {
	"rule": "ci-tools",
	"verdict": "tool list empty",
	"subjects": [{"path": manifest_path}],
} if {
	manifest_lines
	count(declared) == 0
}

# --- direction 2: every pull-request workflow carries a binding list ---------

pr_workflow contains path if {
	some path in workflow_paths
	some line in input.tree.lines[path]
	regex.match(data.batten.patterns["workflow-pull-request-trigger"], line)
}

action_uses(path) := count([1 |
	some line in input.tree.lines[path]
	contains(line, "uses: jdx/mise-action")
])

list_count(path) := count([1 |
	some line in input.tree.lines[path]
	regex.match(data.batten.patterns["install-args-line"], line)
])

# One list per use is the invariant, and a COUNT is decidable without tracking
# block structure — the same constraint the scan above already works within.
violation contains {
	"rule": "ci-tools",
	"verdict": "tool select missing",
	"subjects": [{"path": path}],
} if {
	some path in pr_workflow
	action_uses(path) > 0
	list_count(path) != action_uses(path)
}

binds(path, pattern_id) if {
	some line in input.tree.lines[path]
	regex.match(data.batten.patterns[pattern_id], line)
}

violation contains {
	"rule": "ci-tools",
	"verdict": "tool pin loose",
	"subjects": [{"path": path}],
} if {
	some path in pr_workflow
	action_uses(path) > 0
	list_count(path) == action_uses(path)
	not both_auto_installs_bound(path)
}

both_auto_installs_bound(path) if {
	binds(path, "mise-task-auto-install-off")
	binds(path, "mise-exec-auto-install-off")
}

# --- direction 3: a spawned tool the manifest owns is on the list ------------

spawned contains tool if {
	some line in input.tree.lines[policy_path]
	some hit in regex.find_n(data.batten.patterns["mise-exec-spawn"], line, -1)
	tool := split(hit, " ")[count(split(hit, " ")) - 1]
	tool in owned
}

installed_basenames contains basename(row.tool) if {
	some row in requested
}

violation contains {
	"rule": "ci-tools",
	"verdict": "spawn reach absent",
	"subjects": [{"artifact": tool}],
} if {
	count(requested) > 0
	some tool in spawned
	not tool in installed_basenames
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves a declared
# `line_sources` GLOB over EVERY workflow (CLOUD-845), and direction 2 is entirely
# that: its whole finding was that the retiring gate had been pointed at one file
# that happened to be compliant, so a resolution reaching only some workflows
# reintroduces exactly the blindness CLOUD-812 measured.
# `crates/batten/tests/it/ci_tools.rs` is that tier.

tree(files) := {"tree": {"lines": files}}

manifest := ["[tools]", "rust = \"1.97\"", "\"aqua:open-policy-agent/opa\" = \"1.0\"", "[env]"]

bound := [
	"      env:",
	"        MISE_TASK_RUN_AUTO_INSTALL: \"false\"",
	"        MISE_EXEC_AUTO_INSTALL: \"false\"",
]

pr_flow(entries) := array.concat(
	array.concat(["on:", "  pull_request:", "jobs:", "  ci:", "    steps:", "      - uses: jdx/mise-action@abc"], entries),
	bound,
)

test_a_resolving_list_is_clean if {
	count(violation) == 0 with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust aqua:open-policy-agent/opa"]),
	})
}

test_a_name_no_tools_entry_declares_is_refused if {
	some v in violation with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust zigg"]),
	})
	v.verdict == "tool name unknown"
}

# THE HOLE CLOUD-812 MEASURED: a workflow that declares no list has no names to
# judge, so the first direction passes it.
test_a_pull_request_workflow_with_no_list_is_refused if {
	some v in violation with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust"]),
		".github/workflows/lint.yml": array.concat(
			["on:", "  pull_request:", "jobs:", "  lint:", "    steps:", "      - uses: jdx/mise-action@abc"],
			bound,
		),
	})
	v.verdict == "tool select missing"
}

# A LIST WITHOUT THE VARIABLES IS DECORATIVE.
test_a_list_without_the_auto_install_variables_is_refused if {
	some v in violation with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": [
			"on:",
			"  pull_request:",
			"jobs:",
			"  ci:",
			"    steps:",
			"      - uses: jdx/mise-action@abc",
			"        install_args: rust",
		],
	})
	v.verdict == "tool pin loose"
}

# The ASSIGNMENT, not a mention: a substring search would pass the comment that
# explains why the variable matters, and would pass one setting it true.
test_the_variable_set_true_does_not_bind if {
	some v in violation with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": [
			"on:",
			"  pull_request:",
			"jobs:",
			"  ci:",
			"    steps:",
			"      - uses: jdx/mise-action@abc",
			"        install_args: rust",
			"      env:",
			"        MISE_TASK_RUN_AUTO_INSTALL: \"true\"",
			"        MISE_EXEC_AUTO_INSTALL: \"false\"",
		],
	})
	v.verdict == "tool pin loose"
}

# A scheduled workflow is not on the pull-request path.
test_a_scheduled_workflow_is_out_of_scope if {
	count(violation) == 0 with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust"]),
		".github/workflows/nightly.yml": ["on:", "  schedule:", "jobs:", "  x:", "    steps:", "      - uses: jdx/mise-action@abc"],
	})
}

# THE THIRD DIRECTION: a row's spawn that the list does not install fails CLOSED
# in CI while passing locally.
test_a_spawned_tool_the_list_omits_is_refused if {
	some v in violation with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["check = \"mise exec -- opa check -s schema/ policy/\""],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust"]),
	})
	v.verdict == "spawn reach absent"
}

# Scoped to what the manifest OWNS: a binary that arrives bundled, pre-installed
# or vendored does not belong in an install list, and all three came back as
# findings on the first run of that block.
test_a_spawn_the_manifest_does_not_own_is_not_a_finding if {
	count(violation) == 0 with input as tree({
		"mise.toml": manifest,
		"batten.toml": ["check = \"mise exec -- gh pr view\""],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust aqua:open-policy-agent/opa"]),
	})
}

test_a_manifest_declaring_no_tools_is_could_not_look if {
	some v in violation with input as tree({
		"mise.toml": ["[env]", "X = \"1\""],
		"batten.toml": ["nothing spawned"],
		".github/workflows/ci.yml": pr_flow(["        install_args: rust"]),
	})
	v.verdict == "tool list empty"
}

#MUTANT-SUITE crates/batten/tests/it/ci_tools.rs
#MUTANT unknown-tool-name-passes|s@^\tnot row.tool in declared$@\tfalse@|a_name_no_tools_entry_declares_is_refused
#MUTANT pr-workflow-may-omit-install-args|s@^\tlist_count(path) != action_uses(path)$@\tfalse@|a_pull_request_workflow_with_no_list_is_refused
#MUTANT pr-workflow-list-may-be-nonbinding|s@^\tnot both_auto_installs_bound(path)$@\tfalse@|a_list_without_the_auto_install_variables_is_refused
#MUTANT spawned-tool-need-not-be-installed|s@^\tnot tool in installed_basenames$@\tfalse@|a_spawned_tool_the_list_omits_is_refused
