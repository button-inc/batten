# METADATA
# description: |
#   Every policy package binds `input` to a schema, so no module is silently
#   unchecked by `opa check -s` (CLOUD-876).
#
#   THIS IS THE CLAUSE THAT SEPARATES A GATE FROM THEATRE, and the measurement is
#   why. With a schema DIRECTORY, `opa check -s` does not type an unannotated
#   module against anything: unconstrained paths are `Any`. Measured 2026-08-22, a
#   module reading `input.tree.trackd` with no `# METADATA schemas:` block exits
#   **0**. Annotated, the same typo is `rego_type_error: undefined ref`. So the
#   type check is worth exactly as much as the annotation coverage, and nothing
#   else in the toolchain notices a module that has none.
#
#   AGGREGATE, BECAUSE THE BINDING IS PER-PACKAGE AND THE CORPUS IS PER-FILE. A
#   `# METADATA schemas:` block has package scope, and OPA refuses a
#   redeclaration — `rego_type_error: package annotation redeclared` — so two
#   modules sharing a package share one binding, declared in whichever file
#   happens to own it. A per-file rule would therefore report the other file as
#   unbound, which is a false positive, and a gate whose first firing is a false
#   positive gets an exception written for it. The exception is what rots.
#
#   So the predicate is COVERAGE, not possession: a package is bound if any of its
#   modules declares the block, and every module of an unbound package is named.
#   Naming every module rather than one is deliberate — the reader has to know
#   which files go unchecked, and "add it to one of these" is the honest remedy.
package custom.regal.rules.schemas["every-package-binds-input"]

import data.regal.ast
import data.regal.result

# THE FILE AND LOCATION TRAVEL IN `aggregate_data`, not in `aggregate_source`,
# and that is a correctness requirement rather than a style choice. Measured
# 2026-08-22 under Regal 0.42.0: `result.aggregate` puts only `package_path` in
# `aggregate_source`, so `result.fail(chain, entry.aggregate_source)` reported
# `file: ""` — a violation naming no file, which is non-negotiable rule 4's
# pointer with the pointer removed. Worse, entries for two modules of one package
# were then IDENTICAL and collapsed by set identity, so the second unchecked file
# went unreported entirely. Carrying the name makes each entry distinct and the
# violation a real `path:line`.
#
# METADATA
# description: collects, per module, its package and whether it binds `input`
aggregate contains entry if {
	entry := result.aggregate(rego.metadata.chain(), {
		"package": ast.ref_to_string(input["package"].path),
		"binds": binds_input,
		"file": input.regal.file.name,
		"location": result.location(input["package"]).location,
	})
}

# A module binds `input` when its PACKAGE annotation names the `input` path in a
# `schemas` list. The path is the predicate, not the mere presence of a `schemas`
# key: an annotation binding some other document would satisfy a presence test
# while leaving `input` exactly as unchecked as before.
#
# TWO THINGS HERE WERE FOUND BY BEING WRONG, and both are recorded because both
# fail SILENTLY — a predicate that never matches reports the whole corpus unbound
# while looking correct, which is how a linter rule becomes the thing it lints.
#
#   1. Annotations are at `input["package"].annotations`, NOT `input.annotations`.
#      Regal's parsed module carries only `package`, `imports`, `rules`,
#      `comments` and `regal` at the top level; there is no `annotations` key
#      there at all, so the obvious spelling is undefined rather than empty.
#   2. Regal's `path` is a STRING array, `["input"]`. `opa inspect -a` gives the
#      ref-term form `[{"type": "var", "value": "input"}]` for the same
#      annotation. Reading either tool's shape into the other matches nothing.
#
# Measured at each step: both wrong versions reported 3 violations over a corpus
# that is fully annotated.
default binds_input := false

binds_input if {
	some annotation in input["package"].annotations
	some binding in annotation.schemas
	binding.path == ["input"]
}

# METADATA
# schemas:
#   - input: schema.regal.aggregate
aggregate_report contains violation if {
	some pkg in unbound_packages
	some entry in input.aggregate
	entry.aggregate_data["package"] == pkg

	# `result.fail` resolves the file from `input.regal.file.name`, which does not
	# exist here — the aggregate report's input is the collection, not a module.
	# So the file is unioned back in from the entry that carried it.
	violation := object.union(
		result.fail(rego.metadata.chain(), {"location": entry.aggregate_data.location}),
		{"location": {"file": entry.aggregate_data.file}},
	)
}

# A package no module of which binds `input`. Computed as a set difference rather
# than a per-entry negation, because `binds` is a property of the PACKAGE and any
# one module may legitimately lack the block.
unbound_packages := seen - bound if {
	seen := {entry.aggregate_data["package"] | some entry in input.aggregate}
	bound := {entry.aggregate_data["package"] |
		some entry in input.aggregate
		entry.aggregate_data.binds
	}
}
