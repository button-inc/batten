package custom.regal.rules.schemas["every-package-binds-input_test"]

import data.custom.regal.rules.schemas["every-package-binds-input"] as rule

# THE NEGATIVE ARM ALONE IS NOT A TEST OF THIS RULE. A suite that only asserts
# `count(r) > 0` over an unannotated module passes unchanged if `binds_input` is
# hard-wired to `false` — which is exactly the failure mode this rule's own
# comments record having hit twice (annotations read from the wrong path, and a
# ref-term shape read as a string array). Both wrong versions reported the whole
# corpus unbound while looking correct. So every arm below is paired: the rule
# has to DISCRIMINATE.
#
# `with` cannot appear in a rule head, so each test builds its own aggregate
# inline rather than sharing a helper. That is Regal's own test shape.
#
# `regal.parse_module` does NOT set `input.regal.file.name`, which is where
# `result.aggregate` reads the source file from; without it every entry carries
# the same `aggregate_source` and two modules of one package COLLAPSE INTO ONE
# by set identity — a multi-module test would then silently assert the wrong
# arity. `module/2` puts the name back.

# The annotated shape is the one the corpus actually uses: a package-scoped
# `# METADATA` block whose `schemas` list names the `input` path.
annotated := `# METADATA
# schemas:
#   - input: schema["policy-input.schema"]
package batten.example

allow if input.tree.tracked`

unannotated := `package batten.other

allow if input.tree.tracked`

# Same package as `annotated`, no block of its own — legal, and the reason this
# rule aggregates. OPA refuses a redeclaration, so the second module of a bound
# package CANNOT carry the annotation.
sibling_of_annotated := `package batten.example

deny if input.tree.missing`

second_unannotated := `package batten.other

deny if input.tree.missing`

# An annotation that binds something other than `input`. A presence test on the
# `schemas` key would call this bound; the path predicate must not.
binds_elsewhere := `# METADATA
# schemas:
#   - data.foo: schema["policy-input.schema"]
package batten.elsewhere

allow if input.tree.tracked`

module(name, text) := object.union(
	regal.parse_module(name, text),
	{"regal": {"file": {"name": name}}},
)

test_an_annotated_package_is_not_reported if {
	agg := rule.aggregate with input as module("annotated.rego", annotated)

	r := rule.aggregate_report with input.aggregate as agg

	count(r) == 0
}

test_an_unannotated_package_is_reported if {
	agg := rule.aggregate with input as module("unannotated.rego", unannotated)

	r := rule.aggregate_report with input.aggregate as agg

	count(r) == 1
}

# The discriminating case, and the reason a per-file rule would be wrong: the
# unannotated sibling is covered by its package's binding, while the unrelated
# unannotated package is still named. One report, not two, and not zero.
test_coverage_is_per_package_not_per_file if {
	bound := rule.aggregate with input as module("annotated.rego", annotated)
	sibling := rule.aggregate with input as module("sibling.rego", sibling_of_annotated)
	other := rule.aggregate with input as module("unannotated.rego", unannotated)

	r := rule.aggregate_report with input.aggregate as (bound | sibling) | other

	count(r) == 1
	every violation in r {
		endswith(violation.location.file, "unannotated.rego")
	}
}

# Every module of an unbound package is named, deliberately: the reader has to
# know which files go unchecked.
test_every_module_of_an_unbound_package_is_named if {
	first := rule.aggregate with input as module("unannotated.rego", unannotated)
	second := rule.aggregate with input as module("unannotated_two.rego", second_unannotated)

	r := rule.aggregate_report with input.aggregate as first | second

	count(r) == 2
}

test_an_annotation_binding_another_document_does_not_count if {
	agg := rule.aggregate with input as module("elsewhere.rego", binds_elsewhere)

	r := rule.aggregate_report with input.aggregate as agg

	count(r) == 1
}
