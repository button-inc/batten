#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT vacuous-bar-lowered|s@^\tcount(crates_of(lines)) < 2$@\tcount(crates_of(lines)) < 1@|the_supply_chain_preset_refuses_a_vacuous_or_foreign_binary_inventory
#MUTANT foreign-crate-admitted|s@^\tnot entry in declared$@\tfalse@|the_supply_chain_preset_refuses_a_vacuous_or_foreign_binary_inventory
#MUTANT lockfile-pairs-unread|s@^\tstartswith(following, "version = \\"")$@\tfalse@|the_supply_chain_preset_refuses_a_vacuous_or_foreign_binary_inventory
#MUTANT other-families-judged|s@^\tcount(assets_of(lines)) == 1$@\ttrue@|the_supply_chain_preset_refuses_a_vacuous_or_foreign_binary_inventory
# Supply chain: a released binary's own inventory catalogs something, and only
# crates the lockfile declares (CLOUD-263, moved out of a consumer module under
# CLOUD-843).
#
# A Rust binary carries no dependency metadata unless `cargo auditable` embeds
# it, so a scan of an unwrapped build is an empty document that exits 0 — the
# vacuous green this practice exists to refuse. `batten sbom --binary` scans the
# binary and records one `asset\t<name>` line and one `crate\t<name> <version>`
# line per recovered `rust-crate` artifact; this decides.
#
# TWO VERDICTS, each failing a different way:
#
#   cargo list empty   fewer than 2 recovered crates. 0 is an unwrapped build, 1
#                      is the binary cataloging only itself, and both must fail.
#   cargo list wrong   a recovered crate no declared lockfile declares. SUBSET,
#                      never equality: a lockfile spans build- and dev-
#                      dependencies for every target while the audit section
#                      records only what was linked.
#
# NAMES NO PATH AND NO FAMILY (non-negotiable rule 1). The records it judges are
# the ones the consumer's row projects whose SHAPE is a binary inventory —
# exactly one `asset` line and nothing but `crate` lines besides — and the
# lockfiles are whatever the row's `line_sources` declares, read in Cargo's
# `name`-then-`version` layout. A consumer that declares no lockfile has every
# recovered crate foreign, so the refusal is loud rather than a subset test over
# nothing.
#
# Pointer-only (rule 4): the asset name and a count, never a crate name.
package batten.supply_chain

import rego.v1

rules contains "cargo list other"

assets_of(lines) := [trim_prefix(line, "asset\t") | some line in lines; startswith(line, "asset\t")]

# A list, not a set: two identical artifacts count twice.
crates_of(lines) := [trim_prefix(line, "crate\t") | some line in lines; startswith(line, "crate\t")]

# The families shaped like a binary inventory, by what their lines are.
inventories[family] := lines if {
	is_object(input.tree.records)
	some family, lines in input.tree.records
	is_array(lines)
	count(assets_of(lines)) == 1
	count(assets_of(lines)) + count(crates_of(lines)) == count(lines)
}

# `name version` for every package any declared lockfile declares. Cargo writes
# `version` on the line after `name`, so the pair is read positionally.
declared contains sprintf("%s %s", [name, version]) if {
	is_object(input.tree.lines)
	some lock_lines in input.tree.lines
	is_array(lock_lines)
	some i, line in lock_lines
	startswith(line, "name = \"")
	following := lock_lines[i + 1]
	startswith(following, "version = \"")
	name := trim_suffix(trim_prefix(line, "name = \""), "\"")
	version := trim_suffix(trim_prefix(following, "version = \""), "\"")
}

vacuous(lines) if {
	count(crates_of(lines)) < 2
}

foreign(lines) := {entry |
	some entry in crates_of(lines)
	not entry in declared
}

violation contains {
	"rule": "cargo list other",
	"verdict": "cargo list empty",
	"subjects": [{"artifact": assets_of(lines)[0]}, {"count": count(crates_of(lines))}],
} if {
	some lines in inventories
	vacuous(lines)
}

violation contains {
	"rule": "cargo list other",
	"verdict": "cargo list wrong",
	"subjects": [{"artifact": assets_of(lines)[0]}, {"count": count(foreign(lines))}],
} if {
	some lines in inventories
	not vacuous(lines)
	count(foreign(lines)) > 0
}

# --- cases -------------------------------------------------------------------

lock := [
	"[[package]]",
	"name = \"alpha\"",
	"version = \"1.0.0\"",
	"",
	"[[package]]",
	"name = \"beta\"",
	"version = \"2.0.0\"",
]

tree(crates) := {"tree": {
	"records": {"binary-scan": array.concat(["asset\ttool-v1.0.0-x.spdx.json"], [sprintf("crate\t%s", [c]) | some c in crates])},
	"lines": {"Cargo.lock": lock},
}}

test_two_declared_crates_pass if {
	count(violation) == 0 with input as tree(["alpha 1.0.0", "beta 2.0.0"])
}

test_one_crate_is_vacuous if {
	found := violation with input as tree(["alpha 1.0.0"])
	{entry.verdict | some entry in found} == {"cargo list empty"}
}

test_no_crate_is_vacuous if {
	found := violation with input as tree([])
	{entry.verdict | some entry in found} == {"cargo list empty"}
}

test_a_foreign_crate_is_refused if {
	found := violation with input as tree(["alpha 1.0.0", "gamma 3.0.0"])
	{entry.verdict | some entry in found} == {"cargo list wrong"}
}

test_no_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}, "lines": {"Cargo.lock": lock}}}
}

# ANOTHER FAMILY'S `asset` LINES ARE NOT AN INVENTORY: a release's asset list
# names many assets and no crate, and judging it would call every release
# vacuous. Nor is one that carries any other kind of line.
test_a_family_of_another_shape_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"records": {
			"release": ["asset\ta.tar.gz", "asset\tb.tar.gz"],
			"mixed": ["target\tx", "asset\ta.tar.gz"],
		},
		"lines": {"Cargo.lock": lock},
	}}
}

test_null_facts_are_silent if {
	count(violation) == 0 with input as {"tree": {"records": null, "lines": null}}
}
