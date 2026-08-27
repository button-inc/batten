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
# for. It earned its keep on the first run: three modules were missing from the
# first draft of the table, and the rule named all three before a human read it.
#
# IT READS `input.tree.uses`, NOT LINES. CLOUD-762 measured a line predicate
# wrong at four sites in this tree -- two edges it cannot see and two it invents
# -- so a layering gate on lines would ship a known false green. The resolved
# fact costs the same parse and is right about all four.
#
# COVERAGE IS AN EXEMPTION RATHER THAN FOUR MUTATIONS. Four mutation rows were
# written here first and `mise run mutant` refused every one with `no-suite`:
# the runner mutates a gate and asks a BATS suite to go red, and a policy module
# has none because `batten policy test` is wired to no task. That is CLOUD-931
# exactly, and the two sibling policy modules already carry this exemption.
# Writing the suite would add bash to the census CLOUD-843 is retiring, to test a
# module with nine passing cases of its own.
#
# WHAT STANDS IN FOR IT, so the gap is named rather than unmeasured: the
# acceptance clause was observed END TO END. `use crate::journal::Entry` was
# seeded into `cli.rs`, `batten enforce` reported `module-layering`, and the
# finding went away on revert -- clean tree zero, seeded tree one.
#MUTANT-EXEMPT CLOUD-931|no `tests/module-layering.bats` exists: `mutant` resolves a gate's suite as `tests/$gate.bats`, so without one there is no named case a mutation could turn red. `batten policy test` IS wired as of CLOUD-931, but that is the load-time tier and a `with input as` case is not what the mutation runner drives

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`:
#   OPA parses the whole contiguous block that starts the annotation, so prose
#   placed after it reaches the YAML parser and the module fails to load.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.module_layering

import rego.v1

rules contains "module-layering"

# Every module this table has placed. A module in the judged set and absent here
# is refused rather than allowed.
declared_modules := {
	"action", "admission", "attribution", "baseline", "budget", "bypass", "capture", "ci",
	"cli", "commit", "completion", "config", "contract", "decision", "defects",
	"design", "doctor", "drain", "effect", "emission", "epoch", "error", "exec",
	"exit", "facts", "findings", "git", "handler", "hook", "identity", "init",
	"invocation", "journal", "judge", "lib", "lint", "markers", "mint", "outputs",
	"output", "pattern", "policy", "provision", "receipt", "redirect", "refusal",
	"render", "resolve", "rules", "secrets", "session", "severity", "sink",
	"spec", "state", "stop", "store", "surface", "transcript", "trust", "uses",
	"verbs", "verdict", "waiver", "worktree",
	# `brief`, `main` and `selfwrite` were absent from the first draft of this
	# table, and the coverage rule caught all three on its first run against the
	# real tree — which is the property working before any human read it. `main`
	# is the binary entry point rather than a `pub mod` of the library, and it is
	# declared rather than excluded: it is a file in the judged set, and a
	# selector carve-out would be an exemption where a placement is honest.
	"brief", "main", "selfwrite",
	# `patch` arrived with CLOUD-739 and this rule named it before a human did —
	# the same property the three above record, working a second time. `symbols`
	# arrived with CLOUD-760 and it worked a third. `semver` arrived with
	# CLOUD-1050 and it worked a fourth: the module was written, its tests were
	# green, and this rule is what said nobody had placed it.
	"patch", "symbols", "semver",
	# `recorder` arrived with CLOUD-1051 and it worked a fourth time: the module
	# landed undeclared and this rule named it, before any reviewer did. It is a
	# writer rather than a decider — it accumulates what a gate already said — so
	# it sits below `rules` and reaches `exec` for its one spawn, which is the
	# placed adapter `policy/spawn-adapters.rego` requires.
	"recorder",
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
		# `patch -> git` would close a cycle, and the direction is prose the tree
		# already carries rather than an architecture invented here: `patch.rs`
		# opens by saying it computes the identity `git::landing` consumes, and
		# `git.rs` names `crate::patch` as that identity's authority. A back-edge
		# would make the identity depend on the module that asks it for one.
		"patch": {"git"},
		# `symbols -> rules` is `patch -> git` again, one fact family over, and the
		# prose is already in the tree: `symbols.rs` says acquisition is the
		# CALLER's, and `rules::symbols_fact` is that caller. An acquisition module
		# reaching back into the engine that decides when to acquire would make the
		# `Cost::Effect` boundary a convention rather than a direction — and the
		# whole point of the class is that a projection cannot reach the spawn.
		"symbols": {"rules", "hook"},
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
	"verdict": "V-LAYERING-EDGE-FORBIDDEN",
	"subjects": [{"path": path, "line": edge.line}, {"artifact": edge.to}],
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
	"verdict": "V-LAYER-UNPLACED",
	"subjects": [{"path": path}],
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
	"verdict": "V-LAYER-TABLE-DECIDES-NOTHING",
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

# The cycle CLOUD-739's module could close, in the direction that would close it.
test_the_identity_must_not_reach_its_caller if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/patch.rs",
		[internal("git", 12)],
	)
}

# And the declared direction is the whole point: `git` reaching `patch` is the
# arrangement, not a violation.
test_the_caller_may_reach_the_identity if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/git.rs",
		[internal("patch", 12)],
	)
}

# CLOUD-760's edge, and it is the `Cost::Effect` boundary stated as a direction:
# the acquisition module must not reach the engine that decides when to acquire.
test_the_effect_acquisition_must_not_reach_its_caller if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/symbols.rs",
		[internal("rules", 20)],
	)
}

# The declared direction, again the arrangement rather than a violation: `rules`
# resolves the fact once at the boundary, so it is the module that reaches.
test_the_engine_may_reach_the_effect_acquisition if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/rules.rs",
		[internal("symbols", 20)],
	)
}

# The coverage half: a module the table never placed.
test_an_unplaced_module_is_refused_rather_than_allowed if {
	some v in violation with input as judging(
		"crates/batten/src/brand_new.rs",
		[internal("error", 3)],
	)

	# The TOKEN, not a substring of prose (CLOUD-1050). The predicate a test
	# pins is the class it raises, and a token is what makes that assertion
	# exact — a `contains` over a message passed for any rewording that kept
	# three words, and failed for any that did not.
	v.verdict == "V-LAYER-UNPLACED"
}

# A selector that matched nothing reaches this module as an empty set and it says
# NOTHING, deliberately: the engine already skipped the row before evaluation, so
# a second refusal here would fire in every tree that carries no Rust.
test_an_empty_judged_set_is_the_engines_answer_not_this_modules if {
	count(violation) == 0 with input as {"tree": {"uses": {}}}
}
