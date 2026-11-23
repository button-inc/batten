#MUTANT-SUITE crates/batten/tests/it/source_facts.rs
#MUTANT partial-helper-admitted|s@^\tnode.name in rh_partial_helpers(nodes)$@\tfalse@|the_rego_hygiene_preset_refuses_what_bytecode_reads_differently
# Preset `rego-hygiene`, `module bind partial`: a `:=` whose right side can be
# undefined (#1276, CLOUD-2777).
#
# THE TWO EVALUATORS DISAGREE ON EXACTLY THIS STATEMENT. Rego fails a body at a
# `:=` whose right side is undefined; regorus's interpreter does, and so does
# OPA. regorus's bytecode compiler does not: it emits a `NotUndefined` guard
# after every binding context but `:=` (`PlanContext::ColonAssignment` is the
# one `require_defined_values` omits), so `x := f(a)` with `f` undefined for `a`
# binds `Undefined` and the body runs on. Under a `not` over `x`, or with `_` on
# the left (where the statement exists ONLY to assert the right side is
# defined), that is a verdict no case raises. batten splices the guard back in
# before it compiles (`guarded_sources`), which is the backstop; this module is
# the lint, so the source says what both evaluators do and needs no splice.
#
# WHAT IT REFUSES, by the shape of the right side, read off regorus's own parse
# (`input.tree.units`, the Rego backend of `Fact::Units`):
#
#   * any `_ := e` — its only meaning is "e is defined";
#   * `x := a.b` or `x := a[k]` — a lookup, undefined where the key is absent;
#   * `x := f(…)` where `f` is a helper of the same module that is not TOTAL:
#     no `default` rule and no `else` body, so some argument leaves it undefined.
#
# THE FIX IS NEVER A SPLICE. Bind with `=` (unification carries the guard on
# both evaluators, `_ = e` included), or make the helper total with a `default`
# or an `else`. A call to a builtin, or to a helper this module does not define,
# is not refused: its totality is not in this file's parse, which is this
# preset's stated gap rather than a hidden one.
#
# EVERY NAME IS PREFIXED `rh_`: a preset's modules share one `package`.

# METADATA
# description: |
#   Bound to the TREE surface: reads `input.tree.units` over the row's
#   `unit_sources`, never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.rego_hygiene

import rego.v1

rules contains "module bind partial"

# The helpers of one module that a call can leave undefined.
rh_partial_helpers(nodes) := {node.name |
	some node in nodes
	node.kind == "function"
	node.counts.total == false
}

# A binding whose right side can be undefined, by its shape.
rh_undefinable(node, _) if node.counts.wildcard == true

rh_undefinable(node, _) if node.counts.lookup == true

rh_undefinable(node, nodes) if {
	node.name != ""
	node.name in rh_partial_helpers(nodes)
}

# The `is_object` guard comes first: `some … in null` is an evaluation FAULT,
# and a fault takes the whole bundle down rather than missing quietly.
violation contains {
	"rule": "module bind partial",
	"verdict": "module bind partial",
	"subjects": [{"path": path, "line": node.line}],
} if {
	is_object(input.tree.units)
	some path, unit in input.tree.units
	is_array(unit.nodes)
	some node in unit.nodes
	node.kind == "binding"
	rh_undefinable(node, unit.nodes)
}

# --- the load-time tier ------------------------------------------------------

rh_tree(nodes) := {"tree": {"units": {"policy/a.rego": {"nodes": nodes}}}}

rh_helper(name, total) := {"kind": "function", "position": "rule", "line": 5, "name": name, "counts": {"total": total}}

rh_binding(name, wildcard, lookup) := {"kind": "binding", "position": "body", "line": 9, "name": name, "counts": {"wildcard": wildcard, "lookup": lookup}}

test_a_partial_helper_bound_with_colon_equals_is_refused if {
	found := violation with input as rh_tree([rh_helper("subject", false), rh_binding("subject", false, false)])
	{[entry.subjects[0].path, entry.subjects[0].line] | some entry in found} == {["policy/a.rego", 9]}
}

test_a_total_helper_bound_with_colon_equals_is_clean if {
	count(violation) == 0 with input as rh_tree([rh_helper("subject", true), rh_binding("subject", false, false)])
}

test_a_wildcard_binding_is_refused if {
	some v in violation with input as rh_tree([rh_binding("", true, false)])
	v.verdict == "module bind partial"
}

test_a_lookup_binding_is_refused if {
	some v in violation with input as rh_tree([rh_binding("", false, true)])
	v.verdict == "module bind partial"
}

test_a_builtin_or_foreign_call_is_not_refused if {
	count(violation) == 0 with input as rh_tree([rh_binding("split", false, false)])
}

test_no_units_is_silent if {
	count(violation) == 0 with input as {"tree": {"units": null}}
}
