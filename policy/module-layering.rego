# Module layering, enforced over the resolved `use` graph (CLOUD-359).
#
# THE LAYERINGS ARE DOCUMENTED AND GATED BY NOTHING, which is this row's finding.
# `module-map-check` asserts every module APPEARS in the map -- a membership
# check -- and says nothing about any edge, the same census-for-predicate
# substitution `tests-not-deleted` and `assertions-not-gutted` make. A back-edge
# compiled and passed every gate.
#
# WHAT THIS TABLE CONTAINS, AND WHAT IT DELIBERATELY DOES NOT. Only claims the
# tree already states in its own doc comments. The row puts reorganising modules
# out of scope and it is right to: inventing a rank for all 65 modules would be
# declaring an architecture nobody agreed to, under cover of enforcing one. So
# the table is a FORBIDDEN-EDGE set drawn from prose that already exists, and it
# grows when somebody documents another layering.
#
# ABSENCE IS AN ERROR, NOT AN ALLOW. `declared_modules` must name every module in
# the judged set. A module nobody has placed is a hole in the claim, and a table
# that silently allowed it would be the vacuous pass this row cites CLOUD-251
# for. That is the `undeclared_module` violation below, and it earned its keep on
# the first run: three modules were missing from the first draft of the table.
#
# IT READS `input.tree.uses`, NOT LINES. CLOUD-762 measured a line predicate
# wrong at four sites in this tree -- two edges it cannot see and two it invents
# -- so a layering gate on lines would ship a known false green. The resolved
# fact costs the same parse and is right about all four.
#
# THE COMMENT BLOCK BELOW IS PARSED AS YAML, and it must stay the last one before
# `package`: OPA reads the whole contiguous block starting at `# METADATA`, so
# prose placed after it is fed to the YAML parser and the module fails to load.
# Measured here -- an em dash at the start of a continuation line was reported as
# `found character that cannot start any token`, which names the character and
# not the cause.

# COVERAGE, AND WHY IT IS AN EXEMPTION RATHER THAN FOUR MUTATIONS.
#
# Four `#MUTANT` rows were written here first, one per half of the predicate, and
# `mise run mutant` refused them all with `no-suite (tests/module-layering.bats)`:
# the runner mutates a gate and asks a BATS suite to go red, and a policy module
# has none. `batten policy test` is wired to no task, which is CLOUD-931 exactly,
# and `policy/opa-compliance.rego` and `policy/privileged-lane.rego` already
# carry this same exemption for the same reason.
#
# Writing `tests/module-layering.bats` would clear it and is the wrong trade: it
# adds bash to the census CLOUD-843 is retiring, to test a module that already
# has nine of its own cases running green under `batten policy test`.
#
# WHAT STANDS IN FOR IT MEANWHILE, so this is a named gap and not an unmeasured
# one. The acceptance clause was observed END TO END rather than asserted:
# `use crate::journal::Entry` was seeded into `cli.rs`, `batten enforce` reported
# `module-layering`, and the finding went away on revert. Clean tree zero,
# seeded tree one — discriminating in both directions.
#MUTANT-EXEMPT CLOUD-931|a policy module has no bats suite for `mutant` to turn red: `batten policy test` is wired to no task, so its nine cases cannot be reached by the mutation runner

# METADATA`, so
# prose placed after it is fed to the YAML parser and the module fails to load.
# Measured here -- an em dash at the start of a continuation line was reported as
# `found character that cannot start any token`, which names the character and
# not the cause.

# The mutations, each aimed at one half of the predicate. `run-shape.rego` is the
# precedent: a policy module CAN carry these, and an exemption would be weaker
# than what this gate already survived by hand — the acceptance clause was
# observed end to end, seeding `use crate::journal::Entry` into `cli.rs` and
# watching the finding appear and then go on revert.
#MUTANT layering-direction-ignored|s@forbidden\[module_of(path)\]\[edge.to\]@true@|a forbidden edge is refused and its reverse is not
#MUTANT external-edge-judged|s@edge.origin == "internal"@true@|a crate that shares a module name is not a module edge
#MUTANT unplaced-module-allowed|s@not declared_modules\[module_of(path)\]@false@|a module absent from the table is refused rather than allowed
#MUTANT empty-table-passes-quietly|s@count(forbidden) == 0@false@|a table that forbids nothing is a gate that is off

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any` -- the silently
#   unchecked state CLOUD-876 measured.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.module_layering

import rego.v1

rules contains "module-layering"

# Every module this table has placed. A module in the judged set and absent here
# is refused rather than allowed.
declared_modules := {
	"action", "attribution", "baseline", "budget", "bypass", "capture", "ci",
	"cli", "commit", "completion", "config", "contract", "decision", "defects",
	"design", "doctor", "drain", "effect", "emission", "epoch", "error", "exec",
	"exit", "facts", "findings", "git", "handler", "hook", "identity", "init",
	"invocation", "journal", "judge", "lib", "lint", "markers", "outputs",
	"output", "pattern", "policy", "provision", "receipt", "redirect", "refusal",
	"render", "resolve", "rules", "secrets", "session", "severity", "sink",
	"spec", "state", "stop", "store", "surface", "transcript", "trust", "uses",
	"verbs", "waiver", "worktree",
	# `brief`, `main` and `selfwrite` were absent from the first draft of this
	# table, and the coverage rule caught all three on its first run against the
	# real tree — which is the property working before any human read it. `main`
	# is the binary entry point rather than a `pub mod` of the library, and it is
	# declared rather than excluded: it is a file in the judged set, and a
	# selector carve-out would be an exemption where a placement is honest.
	"brief", "main", "selfwrite",
}

# THE FORBIDDEN EDGES, each traceable to prose already in the tree.
#
# `rules -> hook` is the sharpest instance and the row says so: `refusal.rs`
# states that housing the refusal table in `hook` "would make `rules` import
# `hook` and close a module cycle", and `mem:core` repeats it. rustc permits
# mutual `use` inside one crate, so that reasoning is held today by whoever
# remembers it.
#
# The three chains are the layerings `mem:core` and the module docs state, read
# as "a lower tier must not reach a higher one":
#   surface (data) -> cli (typed values) -> lib (dispatch)
#   config (load) -> resolve (precedence) -> trust (judging) -> lint -> epoch
#   store (which store) / findings (what is in it) / journal (how it is written)
forbidden[from] contains to if {
	some from, targets in {
		"rules": {"hook"},
		"surface": {"cli", "lib"},
		"cli": {"lib", "journal"},
		"config": {"resolve", "trust", "lint", "epoch"},
		"resolve": {"trust", "lint", "epoch"},
		"trust": {"lint", "epoch"},
		"lint": {"epoch"},
		"store": {"findings", "journal"},
	}
	some to in targets
}

# The module a judged path denotes. Stem of the file name, which is Rust's own
# mapping from `foo.rs` to module `foo`.
module_of(path) := name if {
	parts := split(path, "/")
	file := parts[count(parts) - 1]
	name := substring(file, 0, count(file) - 3)
}

# A forbidden edge, reported at the line that wrote it.
#
# Pointer-only (non-negotiable rule 4): the path, the line, and the two module
# names. Never the source line — `to` and `item` are path segments, and the text
# that produced them stays on the engine's side.
violation contains {
	"rule": "module-layering",
	"msg": sprintf(
		"%s:%d %s must not reach %s — a layering this tree documents and nothing enforced",
		[path, edge.line, module_of(path), edge.to],
	),
} if {
	some path, edges in input.tree.uses
	some edge in edges
	edge.origin == "internal"
	# Set INDEXING rather than a bare `in` expression: the pinned type checker
	# reports `undefined function internal.member_2` for the latter over a
	# computed set, and indexing says the same thing in a form it can type.
	forbidden[module_of(path)][edge.to]
}

# A module nobody placed. An implicit allow here is the hole this table exists to
# close, so it is a finding rather than silence.
violation contains {
	"rule": "module-layering",
	"msg": sprintf(
		"%s is judged by the layering rule and absent from its table; place it or narrow the row's selector",
		[path],
	),
} if {
	some path, _ in input.tree.uses
	not declared_modules[module_of(path)]
}

# THE VACUITY GUARD, and the row demands it by name: "an empty or unsatisfiable
# layer table fails rather than passing quietly". A table that forbids nothing
# reporting "no violations" is CLOUD-251's failure mode, and the reason a gate
# can be switched off by deletion without anything going red.
violation contains {
	"rule": "module-layering",
	"msg": "the layer table forbids no edge, so this rule decides nothing — a gate that cannot refuse is off",
} if {
	count(forbidden) == 0
}

# THE OTHER HALF OF VACUITY IS THE ENGINE'S, NOT THIS MODULE'S. A selector that
# matched no file is `NotObserved::RuleSkipped` in `rules::evaluate` — reported
# as not-observed rather than as clean, which is the same three-valued answer
# this module would give and is given once rather than twice. A violation here
# too would fire in every consumer tree that carries no Rust, which is a rule
# refusing a repository for not being this one (measured: a fixture repo with no
# `crates/` tripped it).

# The predicate's own tests. The ALLOW cases are the load-bearing half: a rule
# that fired on everything would satisfy every deny below and gate nothing.

# One judged file whose module is declared and whose edges are given.
judging(path, edges) := {"tree": {"uses": {path: edges}}}

internal(to, line) := {"to": to, "item": "x", "origin": "internal", "via-root": false, "line": line}

test_the_documented_cycle_claim_is_refused if {
	some v in violation with input as judging(
		"crates/batten/src/rules.rs",
		[internal("hook", 52)],
	)
	v.rule == "module-layering"
}

# The row's own acceptance clause, spelled as a case.
test_the_acceptance_clause_edge_is_refused if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/cli.rs",
		[internal("journal", 17)],
	)
}

test_a_documented_chain_is_refused_in_the_wrong_direction if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/config.rs",
		[internal("trust", 44)],
	)
}

# THE DIRECTION IS THE POINT. The same pair the other way round is the layering
# working as documented, and a rule that refused both would be banning the edge
# rather than ordering it.
test_the_same_chain_is_clean_in_the_declared_direction if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/trust.rs",
		[internal("config", 44)],
	)
}

test_an_unrelated_edge_is_not_this_rules_business if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/hook.rs",
		[internal("receipt", 47)],
	)
}

# An EXTERNAL edge is not a module edge. Without this the rule would fire on a
# crate that happens to share a module's name.
test_an_external_edge_is_never_a_layering_violation if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/rules.rs",
		[{"to": "hook", "item": "x", "origin": "external", "via-root": false, "line": 9}],
	)
}

# The coverage half: a module the table never placed.
test_an_unplaced_module_is_refused_rather_than_allowed if {
	some v in violation with input as judging(
		"crates/batten/src/brand_new.rs",
		[internal("error", 3)],
	)
	contains(v.msg, "absent from its table")
}

# A selector that matched nothing reaches this module as an empty set and it says
# NOTHING, deliberately: the engine already skipped the row before evaluation, so
# a second refusal here would fire in every tree that carries no Rust.
test_an_empty_judged_set_is_the_engines_answer_not_this_modules if {
	count(violation) == 0 with input as {"tree": {"uses": {}}}
}
