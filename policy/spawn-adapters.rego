# WHICH MODULES MAY SPAWN, decided by NAME RESOLUTION (CLOUD-760).
#
# This is the consumer that makes `Fact::Symbols` a fact rather than a facility.
# `.claude/rules/rust.md` states the rule it enforces -- a spawn is an inventory
# row, and the annotation beside it is where somebody wrote down whether it
# stays -- but the inventory has never had a gate over WHERE a spawn may appear.
# It has one now, and only this fact could carry it.
#
# WHY NO SCANNER CAN WRITE THIS RULE. `.claude/rules/scanning.md` records the
# three answers to "where is `std::process::Command`": a byte scan says 14, a
# tree-sitter matcher says 11, name resolution says 9. The spread is one import:
# `surface.rs` writes `use clap::{..., Command}`, so the token names a DIFFERENT
# TYPE there, and a call expression looks identical whichever type it names. A
# gate built on either scanner would report `surface.rs` as an unplaced spawning
# module, and the honest remedies for that false positive are all worse than the
# rule -- an exemption for a module that spawns nothing, or a deleted rule.
#
# So the input here is the resolved census, which excludes `surface.rs` because
# the compiler knows what the name means. The measurement is in
# `crates/batten/tests/symbols.rs`, which asserts that exclusion as a SET rather
# than as a count: on this tree the byte and resolved tiers both total 16 and
# disagree about which files they name, so a count comparison would have passed
# while the tiers agreed about nothing.
#
# THE TABLE IS A PLACEMENT, NOT AN ALLOW-LIST OF SITES. It says which modules own
# a delegated tool, each with the tool it delegates to. It deliberately does not
# bound how many spawns a placed module holds: that is the `#[expect(...)]`
# inventory's job, self-cleaning in both directions, and duplicating it here
# would be a second authority that drifts.
#
# COULD-NOT-LOOK IS NOT CLEAN (CLOUD-251). `input.tree.symbols` is `null` when no
# row declared the fact and when the analyser could not be run or parsed, and
# either way this module must not report a tree with no unplaced spawns. It
# refuses instead, which is the same posture `symbols.rs` carries from
# `secrets.rs`: clean is never inferred from a stream that failed to parse.
#
# NO BATS SUITE, for the reason its two siblings carry: `batten policy test` is
# wired to no task, so `mutant` cannot reach a policy module's own cases.
# WHAT STANDS IN FOR IT: the acceptance clause was observed END TO END. A
# `std::process::Command::new("true")` was seeded into `crates/batten/src/git.rs`
# -- a module the table does not place, and the one CLOUD-739/740 spent the
# campaign emptying of spawns -- `batten check` reported `spawn-adapters`, and the
# findings went away on revert. Clean tree ZERO, seeded tree TWO: the seed's
# signature and its call each resolve the type, which is the resolved tier
# counting a USE rather than an occurrence of `::new`, exactly as the fact's own
# suite records for `exec.rs`.
#MUTANT-EXEMPT CLOUD-931|a policy module has no bats suite for `mutant` to turn red: `batten policy test` is wired to no task, so its cases cannot be reached by the mutation runner

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.spawn_adapters

import rego.v1

rules contains "spawn-adapters"

# The placed adapters, each named with what it delegates to. Measured against the
# tree rather than imagined: this is exactly the resolved set on the commit that
# introduced the rule, so the gate starts true and every later row is a decision
# somebody made.
# A SET, and deliberately not a name -> reason map, which is what this table was
# first written as. `descend` in `policy.rs` walks every object member looking for
# a `rules` rule, and one of the placements below IS the `rules` module — so the
# map's own key shadowed the bundle's published id and the engine refused the
# whole module with "answered `rules` with a shape that is not a set of ids".
# Measured here before the rule ever ran. The reasons live in the comment.
#
#   exec       the sanctioned child-process boundary
#   provision  installs the binaries the other adapters pin
#   secrets    the pinned ripsecrets adapter (CLOUD-59)
#   symbols    the pinned clippy adapter, this fact's own acquisition (CLOUD-760)
#   judge      the judge kind's delegated command
#   handler    the harness handler boundary
#   action     an action row RUNS a command; that is the kind's definition
#   rules      the engine that runs a `command` row's `check` and `fix`
adapters := {
	"exec", "provision", "secrets", "symbols",
	"judge", "handler", "action", "rules",
}

module_of(path) := name if {
	parts := split(path, "/")
	file := parts[count(parts) - 1]
	name := substring(file, 0, count(file) - 3)
}

# A spawn in a module the table has not placed.
#
# Pointer-only (non-negotiable rule 4): the path, the line and the module name.
# The analyser's diagnostic and the source line it quoted are not in the fact at
# all, so there is nothing here for this module to leak even by mistake.
violation contains {
	"rule": "spawn-adapters",
	"msg": sprintf(
		"%s:%d %s resolves the spawn type and is not a placed adapter — route it through `exec`, or place the module with the tool it delegates to",
		[site.path, site.line, module_of(site.path)],
	),
} if {
	some site in input.tree.symbols.sites
	site.lint == "clippy::disallowed_types"
	not adapters[module_of(site.path)]
}

# COULD NOT LOOK. `null` is both did-not-look answers, and neither is clean.
violation contains {
	"rule": "spawn-adapters",
	"msg": "the symbol census is absent, so no spawn was placed or refused -- declare `symbols = true` on this row, or install the analyser",
} if {
	not input.tree.symbols
}

# THE VACUITY GUARD. A table placing nothing decides nothing, and a rule that
# cannot refuse is off.
violation contains {
	"rule": "spawn-adapters",
	"msg": "the adapter table places no module, so this rule decides nothing -- a gate that cannot refuse is off",
} if {
	count(adapters) == 0
}
