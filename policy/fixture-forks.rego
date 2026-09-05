# CLOUD-1419's ratchet: the integration suite does not grow a new hand-rolled
# `git init`.
#
# WHAT IT IS FOR, MEASURED RATHER THAN ASSERTED. One traced run
# (`GIT_TRACE2_EVENT`, one trace file per git process) spends **9,476 git
# processes and 25.17s** across the suite. `init` is **1,819 of them, 4.49s**,
# and the tree holds only **79** hand-rolled `git init` call sites — so a call
# site is spent roughly twenty times per run, which is why the reshaping is worth
# doing and why nothing here counts call sites.
#
# The fixture builds its repository by copying a template published once per
# filesystem instead. This is what stops that reversing: a new fixture that forks
# `git init` for itself is refused at the line that does it.
#
# THIS MODULE IS THE WHOLE GATE, AND THERE IS NO AGGREGATE RATCHET BESIDE IT.
#
# A `kind = "ratchet"` row over `git_in(` was written in the same branch as this
# module and withdrawn in it. It counted CALL SITES, and the measurement above is
# why that fails: 79 hand-rolled sites produce 1,819 processes, so the template
# removed 1,008 processes while ADDING 17 call sites, and the row refused its own
# enabling change. `batten.toml` carries the withdrawal and its reasoning.
#
# So the question this module answers is not "the pointer half" of a pair — it is
# the question, and it is a per-file COMPARISON rather than a total: was a fork
# ADDED to a file, or did a file END the change with more than it started with?
# `input.tree["base-delta"]` carries the paths and the base side of an edited
# path's lines, which is exactly what that needs.
#
# THE AGGREGATE IS NOT LEFT UNCOVERED BY THIS. A total can only grow through a
# fork appearing in some file, and a fork appearing in some file is what the two
# arms below read — at a `path:line` a reader opens, rather than as a count they
# have to reconstruct.
#
# NO CEILING IS WRITTEN DOWN, for `bash-surface-not-growing`'s reason: a number
# in a file is a second authority over a count the engine computes. What is
# declared here is a SHAPE — a fixture that forks — and the base delta is the
# comparison already.
#
# THE ADMISSION IS A DECLARATION, NOT A PROOF, and it is deliberately the weaker
# half. `# needs-real-fixture:` is read from the WORKING tree, because an added
# file is absent from base and there is nowhere else to read it — so a change CAN
# write its own permission. What it buys is a silent regrowth becoming a visible,
# attributed one, which is worth having and is not the same guarantee as
# `retires_with`'s.
#
# SCOPE IS THE INTEGRATION SUITE AND NOT THE HARNESS. `common/mod.rs` is where
# the one surviving `git init` LIVES — it builds the template every other fixture
# copies — so a rule refusing it would refuse the mechanism it exists to protect.
# That is an exemption by path and it is stated rather than implied.
#MUTANT-SUITE crates/batten/tests/it/fixture_forks.rs
#MUTANT added-init-unread|s@^\tsome index, line in input.tree.lines\[path\]$@\tsome index, line in []@|an_added_fixture_that_forks_git_init_is_refused
#MUTANT harness-exemption-may-widen|s@^\tnot exempt_path(path)$@\ttrue@|the_harness_module_may_still_build_the_template
#
# THE FIRST MUTATION EMPTIES THE LINE WALK rather than negating the pattern
# match, and that is the discriminating choice: negating the match would also be
# excluded by the scope conjunct on every fixture path, so it would survive over
# a tree with no fixtures at all. Emptying the walk makes the added-file arm
# decide nothing while every other conjunct still holds.
#
# THE SECOND NEUTERS THE HARNESS EXEMPTION, so the case that must redden is the
# PASS-side one — `common/mod.rs` building the template. A gate that refuses its
# own mechanism is the shape that gets switched off, and this is what says it
# does not.

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.fixture_forks

import rego.v1

rules contains "fixture-fork-added"

# The branch's own diff. NULL when the base rev does not resolve.
#
# **GOING SILENT IS NOT ABSTAINING, AND THIS PARAGRAPH CLAIMED IT WAS** (review
# of #848). It read "could-not-look, never a fabricated empty delta that would
# pass the gate on ignorance" — but a null `delta` makes `delta.added` undefined,
# both refusing clauses go quiet, the `missing` clause below still evaluates so
# the module does NOT report `RuleSkipped`, and the result is ZERO FINDINGS at
# exit 0. Silence and a pass are byte-identical on the decision surface, which is
# the whole thing this module's own header says it refuses.
#
# Measured shape: a shallow clone, a detached CI checkout with the base
# unfetched, or a fork with no `origin/main` — a branch adding a whole file of
# forked fixtures passes.
delta := input.tree["base-delta"]

# THE COULD-NOT-LOOK ARM, which `spawn-widening.rego` carries for the same fact
# and this did not. A base that will not resolve is reported rather than passed.
violation contains {
	"rule": "fixture-fork-added",
	"verdict": "diff read absent",
	"subjects": [{"path": "batten.toml"}],
} if {
	not input.tree["base-delta"]
}

# A `[[pattern]]` ROW RATHER THAN AN INLINE LITERAL, and not merely because an
# inline regex fails to load. Two spellings of this one concept are live in the
# tree — `&["init", "-q"]` and `&["init", "--quiet"]` — which is exactly the
# duplication the registry exists to make unwritable: a second author reaching
# for a third spelling would have to add a row rather than a line.
init_fork := data.batten.patterns["fixture-git-init"]

# The integration suite's own modules.
#
# `crates/batten/tests/it/` and a `.rs` suffix. Fixture data under `tests/` is
# not a fixture module, and the lib unit tests build no repositories at all.
in_scope(path) if {
	startswith(path, "crates/batten/tests/it/")
	endswith(path, ".rs")
}

# The harness itself, which owns the one `git init` that survives.
exempt_path(path) if path == "crates/batten/tests/it/common/mod.rs"

# A file that declares it needs a real repository, read from the WORKING tree.
declared(path) if {
	some line in input.tree.lines[path]
	contains(line, "// needs-real-fixture:")
}

# How many lines of `path` fork `git init`, as the working tree has it.
forks_now(path) := count([index |
	some index, line in input.tree.lines[path]
	regex.match(init_fork, line)
])

# And as the base rev had it. `base-lines` carries the base side of every EDITED
# path, which is what makes the edited arm a comparison rather than a snapshot.
forks_at_base(path) := count([index |
	some index, line in delta["base-lines"][path]
	regex.match(init_fork, line)
])

# AN ADDED FIXTURE THAT FORKS. Every matching line is new by construction — the
# file is absent from base — so each one is a finding with its own pointer.
violation contains {
	"rule": "fixture-fork-added",
	"verdict": "spawn add refused",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some path in delta.added
	in_scope(path)
	not exempt_path(path)
	not declared(path)
	some index, line in input.tree.lines[path]
	regex.match(init_fork, line)
}

# AN EDITED FIXTURE THAT GREW ONE. A count comparison rather than a line
# comparison: a fixture legitimately moves its existing calls around, and
# refusing a moved line would fire on ordinary editing — the shape a gate does
# not survive. Only the total growing is the reversal this refuses.
#
# The pointer is the FIRST forking line, because that is what a reader opens; the
# rule is about the file's total, so naming every line would report a count as a
# list.
violation contains {
	"rule": "fixture-fork-added",
	"verdict": "spawn add refused",
	"subjects": [{"path": path, "line": first_fork(path)}],
} if {
	some path in delta.edited
	in_scope(path)
	not exempt_path(path)
	not declared(path)
	forks_now(path) > forks_at_base(path)
}

first_fork(path) := min([found |
	some index, line in input.tree.lines[path]
	regex.match(init_fork, line)
	found := index + 1
])

# COULD NOT LOOK IS A FINDING, NOT A PASS. A declared source that will not parse
# belongs in `missing` rather than being silently absent, and a module that
# iterates only the delta reports green over a file it never read.
violation contains {
	"rule": "fixture-fork-added",
	"verdict": "source read unread",
	"subjects": [{"path": path}],
} if {
	some path, _cause in input.tree.missing
	in_scope(path)
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. What they cannot pin is that the engine BUILDS the
# input the predicate reads — `with input as` fabricates the very shape the
# engine may be unable to produce — so `crates/batten/tests/it/fixture_forks.rs`
# runs the same questions over the compiled binary against a real base ref. Both
# tiers, per `.claude/rules/policy-modules.md`, and the second is not optional.

patterns := {"fixture-git-init": `\["init", "--?q`}

tree(added, edited, lines, base_lines) := {"tree": {
	"base-delta": {
		"added": added,
		"edited": edited,
		"deleted": [],
		"base-lines": base_lines,
	},
	"lines": lines,
	"missing": {},
}}

forking := `    git_in(&dir, &["init", "-q"]);`

quiet := `    git_in(&dir, &["init", "--quiet"]);`

test_an_added_fixture_that_forks_git_init_is_refused if {
	count(violation) == 1 with input as tree(
		["crates/batten/tests/it/new_gate.rs"],
		[],
		{"crates/batten/tests/it/new_gate.rs": ["fn one() {", forking, "}"]},
		{},
	)
		with data.batten.patterns as patterns
}

# THE SECOND SPELLING REACHES THE SAME ROW, which is the whole argument for the
# registry over an inline literal.
test_the_long_spelling_is_the_same_concept if {
	count(violation) == 1 with input as tree(
		["crates/batten/tests/it/new_gate.rs"],
		[],
		{"crates/batten/tests/it/new_gate.rs": [quiet]},
		{},
	)
		with data.batten.patterns as patterns
}

# THE POINTER IS A LINE, not a file — rule 4's shape for a finding a reader has
# to open.
test_the_finding_points_at_the_forking_line if {
	some v in violation with input as tree(
		["crates/batten/tests/it/new_gate.rs"],
		[],
		{"crates/batten/tests/it/new_gate.rs": ["fn one() {", forking, "}"]},
		{},
	)
		with data.batten.patterns as patterns
	v.subjects[0].line == 2
}

# THE PASS SIDE FIRST: without it every refusal above is satisfied by a module
# that refuses everything.
test_an_added_fixture_that_forks_nothing_is_clean if {
	count(violation) == 0 with input as tree(
		["crates/batten/tests/it/new_gate.rs"],
		[],
		{"crates/batten/tests/it/new_gate.rs": ["let dir = Fixture::new(\"x\").git().build();"]},
		{},
	)
		with data.batten.patterns as patterns
}

# THE CASE THAT KEEPS THE GATE FROM REFUSING ITS OWN MECHANISM. `common/mod.rs`
# is where the surviving `git init` builds the template every other fixture
# copies. `#MUTANT harness-exemption-may-widen` reddens exactly here.
test_the_harness_module_may_still_build_the_template if {
	count(violation) == 0 with input as tree(
		["crates/batten/tests/it/common/mod.rs"],
		[],
		{"crates/batten/tests/it/common/mod.rs": [forking]},
		{},
	)
		with data.batten.patterns as patterns
}

# AN EDITED FILE IS A COMPARISON, NOT A SNAPSHOT. Moving an existing call is
# ordinary editing and must not fire.
test_an_edited_fixture_that_moved_its_fork_is_clean if {
	count(violation) == 0 with input as tree(
		[],
		["crates/batten/tests/it/walker.rs"],
		{"crates/batten/tests/it/walker.rs": ["fn a() {", forking, "}"]},
		{"crates/batten/tests/it/walker.rs": [forking, "fn a() {", "}"]},
	)
		with data.batten.patterns as patterns
}

test_an_edited_fixture_that_grew_a_fork_is_refused if {
	count(violation) == 1 with input as tree(
		[],
		["crates/batten/tests/it/walker.rs"],
		{"crates/batten/tests/it/walker.rs": [forking, quiet]},
		{"crates/batten/tests/it/walker.rs": [forking]},
	)
		with data.batten.patterns as patterns
}

# THE ADMISSION, and it is read from the working tree because an added file has
# no base side to read it from.
test_a_declared_fixture_owns_its_fork if {
	count(violation) == 0 with input as tree(
		["crates/batten/tests/it/new_gate.rs"],
		[],
		{"crates/batten/tests/it/new_gate.rs": [
			"// needs-real-fixture: CLOUD-1 the subject is git init itself",
			forking,
		]},
		{},
	)
		with data.batten.patterns as patterns
}

# ANTI-VACUITY ON THE SCOPE. A path outside the integration suite has the same
# content and is not this rule's business — without the anchor the rule would
# refuse the engine's own source, and with a wrong anchor it would refuse nothing
# at all while still passing every case above.
test_a_path_outside_the_suite_is_not_this_rules_business if {
	count(violation) == 0 with input as tree(
		["crates/batten/src/git.rs"],
		[],
		{"crates/batten/src/git.rs": [forking]},
		{},
	)
		with data.batten.patterns as patterns
}

# FIXTURE DATA IS NOT A FIXTURE MODULE.
test_a_non_rust_path_in_the_suite_is_not_judged if {
	count(violation) == 0 with input as tree(
		["crates/batten/tests/it/fixtures/sample.json"],
		[],
		{"crates/batten/tests/it/fixtures/sample.json": [forking]},
		{},
	)
		with data.batten.patterns as patterns
}

# COULD NOT LOOK. A null `base-delta` goes silent rather than reading as an empty
# diff.
test_an_unresolvable_base_refuses_nothing if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": null,
		"lines": {},
		"missing": {},
	}}
		with data.batten.patterns as patterns
}

# AND A SOURCE THAT WOULD NOT PARSE IS A FINDING RATHER THAN A CLEAN TREE.
test_an_unreadable_fixture_is_reported_rather_than_skipped if {
	some v in violation with input as {"tree": {
		"base-delta": {"added": [], "edited": [], "deleted": [], "base-lines": {}},
		"lines": {},
		"missing": {"crates/batten/tests/it/walker.rs": "Unparsed"},
	}}
		with data.batten.patterns as patterns
	v.verdict == "source read unread"
}
