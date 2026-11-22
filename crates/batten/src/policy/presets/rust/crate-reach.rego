#MUTANT-SUITE crates/batten/tests/it/preset_manifest.rs
#MUTANT unlisted-admitted|s@^\tnot regex.match(allow, other)$@\tfalse@|the_rust_preset_suite_passes
# Preset `rust`, `crate reach unknown`: a workspace package reaches a workspace package its
# `crate-allow-<package>` pattern does not admit (CLOUD-2798).
#
# A crate boundary stops a module cycle, but nothing stops a `Cargo.toml` edit
# from adding an edge that turns a wide crate graph back into a deep one. "The
# most important property of a crate is which crates it doesn't (transitively)
# depend on" (Kladov, *Fast Rust Builds*). So each package's allowed reach is
# reviewable data, one `[[pattern]]` row per package in the consumer's
# `batten.toml`, and this module refuses a
# reached name the row does not match, naming both. A package with NO row is
# refused too: a new crate cannot dodge the gate by being undeclared.
#
# The reached sets are the `crate-reach` record, written by
# `mise run crate-reach-record` from the activated `cargo metadata` graph
# (`cargo_graph`'s activation rule). No crate name is spelled here (rule 1).

# METADATA
# description: |
#   Bound to the TREE surface: reads `input.tree.records["crate-reach"]`, never
#   the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten

import rego.v1

rules contains "crate reach unknown"

rules contains "crate declare missing"

crate_reach_lines := input.tree.records["crate-reach"]

# `reach <package> <a,b,…>`; a package reaching no member has no third field.
crate_reach[name] := reached if {
	some line in crate_reach_lines
	startswith(line, "reach ")
	fields := split(trim_space(substring(line, count("reach "), -1)), " ")
	name := fields[0]
	reached := crate_reached_of(fields)
}

crate_reached_of(fields) := split(fields[1], ",") if count(fields) > 1

crate_reached_of(fields) := [] if count(fields) == 1

crate_allow_of(name) := data.batten.patterns[concat("", ["crate-allow-", name])]

violation contains {
	"rule": "crate reach unknown",
	"verdict": "crate reach unknown",
	"subjects": [{"artifact": name}, {"artifact": other}],
} if {
	some name, reached in crate_reach
	allow := crate_allow_of(name)
	some other in reached
	not regex.match(allow, other)
}

violation contains {
	"rule": "crate declare missing",
	"verdict": "crate declare missing",
	"subjects": [{"artifact": name}],
} if {
	some name, _ in crate_reach
	not crate_allow_of(name)
}

crate_patterns := {
	"crate-allow-low": "^$",
	"crate-allow-top": "^(low|mid)$",
	"crate-allow-mid": "^low$",
}

test_a_package_reaching_an_unlisted_package_is_refused if {
	found := violation with input as {"tree": {"records": {"crate-reach": ["reach mid low,top"]}}}
		with data.batten.patterns as crate_patterns
	count(found) == 1
}

test_a_package_reaching_only_listed_packages_passes if {
	found := violation with input as {"tree": {"records": {"crate-reach": [
		"reach low",
		"reach mid low",
		"reach top low,mid",
	]}}}
		with data.batten.patterns as crate_patterns
	count(found) == 0
}

test_an_undeclared_package_is_refused if {
	found := violation with input as {"tree": {"records": {"crate-reach": ["reach new low"]}}}
		with data.batten.patterns as crate_patterns
	count(found) == 1
}
