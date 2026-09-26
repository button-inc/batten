# Does a binary's own inventory catalog something, and only crates this lockfile
# declares? (CLOUD-263, ported off `mise-tasks/sbom-binary.sh` under CLOUD-1717.)
#
# `sbom` inventories the REPOSITORY at the tag; `sbom-binary` inventories what is
# inside an archive a user downloads. syft against a plain Rust binary recovers 0
# rust-crate packages — a Rust binary carries no dependency metadata unless
# `cargo auditable` embeds it — so a scan of one is an empty document that exits
# 0, the vacuous green CLOUD-258 taught this repo to distrust.
#
# THE SPLIT IS §5's: `check` cannot spawn, so `[tasks.sbom-binary-record]` runs
# syft over the binary, writes the asset, and records the asset's name plus one
# `crate\t<name> <version>` line per recovered `rust-crate` artifact (the type
# filter is the producer's: syft reports the FILE itself as an artifact on some
# inputs, which would pad an empty binary to 1). This decides.
#
# TWO VERDICTS, each failing a different way:
#
#   cargo list empty   fewer than 2 recovered crates. 0 is an unwrapped build, 1
#                      is the binary cataloging only itself, and both must fail.
#   cargo list wrong   a recovered crate that `Cargo.lock` does not declare.
#                      SUBSET, never equality: the lockfile spans build- and
#                      dev-dependencies for every target (189 measured) while the
#                      audit section records only what was linked (85).
#
# AN UNREADABLE LOCKFILE IS NOT A PASS: `declared` is then empty and every
# recovered crate is foreign, so the refusal is loud rather than a subset test
# over nothing. The producer refuses outright on a missing `Cargo.lock` besides.
#
# Pointer-only (rule 4): the asset name and a count, never a crate name.
#
#MUTANT-SUITE crates/batten/tests/it/sbom_binary.rs
#MUTANT vacuous-bar-lowered|s@^\tcount(recovered_list) < 2$@\tcount(recovered_list) < 1@|one_package_is_the_other_vacuous_shape
#MUTANT foreign-crate-admitted|s@^\tnot entry in declared$@\tfalse@|a_crate_absent_from_the_lockfile_fails_naming_counts_not_the_crate
#MUTANT lockfile-pairs-unread|s@^\tstartswith(following, "version = \\"")$@\tfalse@|subset_not_equality_a_larger_lockfile_passes

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.sbom_binary

import rego.v1

rules contains "cargo list other"

lines := input.tree.records["sbom-binary"]

lock_lines := input.tree.lines["Cargo.lock"]

# The asset the producer wrote, which every finding points at.
assets := {trim_prefix(line, "asset\t") | some line in lines; startswith(line, "asset\t")}

pointer := name if {
	count(assets) == 1
	some name in assets
} else := "sbom-binary"

# A list, not a set: two identical artifacts count twice, as the program's
# line count did.
recovered_list := [trim_prefix(line, "crate\t") |
	some line in lines
	startswith(line, "crate\t")
]

# `name version` for every `[[package]]` the lockfile declares. Cargo writes
# `version` on the line after `name`, so the pair is read positionally.
declared contains sprintf("%s %s", [name, version]) if {
	some i, line in lock_lines
	startswith(line, "name = \"")
	following := lock_lines[i + 1]
	startswith(following, "version = \"")
	name := trim_suffix(trim_prefix(line, "name = \""), "\"")
	version := trim_suffix(trim_prefix(following, "version = \""), "\"")
}

foreign contains entry if {
	some entry in recovered_list
	not entry in declared
}

violation contains {
	"rule": "cargo list other",
	"verdict": "cargo list empty",
	"subjects": [{"artifact": pointer}, {"count": count(recovered_list)}],
} if {
	lines
	count(recovered_list) < 2
}

violation contains {
	"rule": "cargo list other",
	"verdict": "cargo list wrong",
	"subjects": [{"artifact": pointer}, {"count": count(foreign)}],
} if {
	count(recovered_list) >= 2
	count(foreign) > 0
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
	"records": {"sbom-binary": array.concat(["asset\tbatten-v9.9.9-x.spdx.json"], [sprintf("crate\t%s", [c]) | some c in crates])},
	"lines": {"Cargo.lock": lock},
}}

test_two_declared_crates_pass if {
	count(violation) == 0 with input as tree(["alpha 1.0.0", "beta 2.0.0"])
}

test_one_crate_is_vacuous if {
	found := violation with input as tree(["alpha 1.0.0"])
	{entry.verdict | some entry in found} == {"cargo list empty"}
}

test_a_foreign_crate_is_refused if {
	found := violation with input as tree(["alpha 1.0.0", "gamma 3.0.0"])
	{entry.verdict | some entry in found} == {"cargo list wrong"}
}

test_no_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}, "lines": {"Cargo.lock": lock}}}
}
