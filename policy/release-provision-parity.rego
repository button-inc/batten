# Every architecture `release-artifacts.yml` publishes is covered by every
# `[[provision]]` platform table, or the gap is declared below.
#
# CLOUD-1431 is the authority on why: the measurement, the two pinned-tool
# surfaces and only one of them gated, and what the runtime already does right.
# Not restated here — the row is the durable home, and a copy in this file drifts
# from it.
#MUTANT-SUITE crates/batten/tests/it/release_provision_parity.rs
#MUTANT gap-may-go-undeclared|s@not declared_gap\[key\]@false@|an_undeclared_platform_gap_is_refused
# THE ARCHITECTURE MUST BE THE ONE THE CASE PINS (CLOUD-1444). This row deleted
# the `aarch64` musl mapping while `a_musl_triple_maps_to_the_same_platform_key_as_gnu`
# pins `x86_64-unknown-linux-musl`, so the mutation removed a row that case never
# resolves and its verdict could not move — `SURVIVED` on every sweep, over a
# suite that was never given anything to see. The suite's own comment states the
# intent correctly ("deleting the musl row from the map"); only the triple was
# wrong, which is why this is a one-token repair and not a new case.
#MUTANT musl-may-not-map|s@"x86_64-unknown-linux-musl": "linux-x86_64",@@|a_musl_triple_maps_to_the_same_platform_key_as_gnu

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_provision_parity

import rego.v1

rules contains "release-target-has-a-provisioned-scanner"

# A rust triple is not a platform key. `provision.rs`'s `platform_key()` builds
# `<os>-<arch>` with no libc flavour, so `-gnu` and `-musl` collapse to one key —
# which is what stops a musl target reading as uncovered when its gnu sibling is
# pinned.
#
# A STATIC OBJECT, not a function with a definition per arm: regorus reads a
# multi-arm function as a multi-value rule and the module would not load. A
# target this map does not name is could-not-look below, never a pass.
platform_of := {
	"x86_64-unknown-linux-gnu": "linux-x86_64",
	"aarch64-unknown-linux-gnu": "linux-aarch64",
	"x86_64-unknown-linux-musl": "linux-x86_64",
	"aarch64-unknown-linux-musl": "linux-aarch64",
	"x86_64-apple-darwin": "macos-x86_64",
	"aarch64-apple-darwin": "macos-aarch64",
	"x86_64-pc-windows-gnu": "windows-x86_64",
}

# A gap earns a row here only when the artifact does not exist upstream to pin,
# verified against the scanner's own releases rather than inferred from a
# refusal. `no-source-built-tool` forbids compiling one.
#
# A DECLARED GAP DOES NOT MAKE THE PLATFORM WORK, and reading it that way is the
# one misreading worth guarding: `batten enforce` there still exits 1 naming the
# missing key — fail-closed and loud, which is a refusal rather than scanning.
# The durable answer is a scanner that ships for these platforms (CLOUD-59).
declared_gap := {
	"linux-aarch64",
	"windows-x86_64",
}

# READ INLINE, NEVER BOUND TO A TOP-LEVEL RULE. Measured on the compiled engine:
# a top-level rule whose VALUE carries a `deny` key at any depth silences the
# whole module, every predicate, including one whose body is `true`.
# `policy/ci-parity.rego` was dead over this tree for as long as it bound
# `mise.toml`, which declares `[tasks.deny]`. `batten.toml` is a policy authority
# full of the word, so binding either document makes this file look clean and
# decide nothing.
published contains target if {
	some _, job in input.tree.documents[".github/workflows/release-artifacts.yml"].jobs
	some entry in job.strategy.matrix.include
	target := entry.target
}

# Every platform key a `[[provision]]` row pins, per row name.
pinned[name] := keys if {
	some row in input.tree.documents["batten.toml"].provision
	name := row.name
	keys := {key | some key, _ in row.platforms}
}

# --- a published target every provision row can serve -------------------------

violation contains {
	"rule": "release-target-has-a-provisioned-scanner",
	"verdict": "release cover partial",
	"subjects": [{"artifact": target}, {"artifact": name}],
} if {
	some target in published
	key := platform_of[target]
	not declared_gap[key]
	some name, keys in pinned
	not keys[key]
}

# --- could not look -----------------------------------------------------------
#
# THE CLAUSE, WRITTEN RATHER THAN LEFT TO ABSTENTION. A module carrying no
# `missing` arm still abstains — the engine reports `RuleSkipped` — but
# abstention is not a finding and nobody reads it. `rules/policy-modules.md`
# is explicit that the difference between "the engine recording that it could not
# look" and "your gate saying so" is this clause.

violation contains {
	"rule": "release-target-has-a-provisioned-scanner",
	"verdict": "workflow read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
}

# A PUBLISHED TARGET THIS MAP DOES NOT NAME IS COULD-NOT-LOOK, NEVER A PASS.
#
# The map is the mapping's one authority, so a triple absent from it is a
# question this rule cannot answer — and answering it as covered is exactly the
# dead-gate shape the whole file guards against. A new release target therefore
# reddens here until the map names it, which is the trigger the gate exists for.
violation contains {
	"rule": "release-target-has-a-provisioned-scanner",
	"verdict": "release cover partial",
	"subjects": [{"artifact": target}],
} if {
	some target in published
	not platform_of[target]
}

# --- the predicate's own tests -------------------------------------------------
#
# The SILENT cases are the load-bearing half, as they are in every module here:
# each skip above is a pass-side property, and a rule that refused every target
# would satisfy the deny cases while deciding nothing.

# NO `deny` KEY ANYWHERE IN THIS VALUE, deliberately: a top-level rule carrying
# one at any depth silences the whole module, which is what the inline document
# reads above exist for.
tree(targets, platforms) := {"tree": {
	"documents": {
		".github/workflows/release-artifacts.yml": {"jobs": {"dist": {"strategy": {"matrix": {"include": [{"target": t} | some t in targets]}}}}},
		"batten.toml": {"provision": [{
			"name": "scanner",
			"platforms": platforms,
		}]},
	},
	"missing": {},
}}

covered := {"linux-x86_64": {"url": "u"}}

test_a_covered_target_is_clean if {
	count(violation) == 0 with input as tree(["x86_64-unknown-linux-gnu"], covered)
}

test_an_uncovered_undeclared_target_is_refused if {
	found := violation with input as tree(["x86_64-apple-darwin"], covered)
	some f in found
	f.rule == "release-target-has-a-provisioned-scanner"
	f.verdict == "release cover partial"
}

# The declared-gap arm, and the one a reviewer should distrust most: it is the
# only thing between this gate and a red tree, so a test letting it pass
# vacuously would make the whole rule unfalsifiable.
test_a_declared_gap_is_silent if {
	count(violation) == 0 with input as tree(["aarch64-unknown-linux-gnu"], covered)
}

test_the_other_declared_gap_is_silent_too if {
	count(violation) == 0 with input as tree(["x86_64-pc-windows-gnu"], covered)
}

# A musl triple resolves to its gnu sibling's key, so pinning one covers both.
test_a_musl_target_is_covered_by_its_gnu_key if {
	count(violation) == 0 with input as tree(["x86_64-unknown-linux-musl"], covered)
}

# A triple the map does not name is could-not-look, and could-not-look refuses.
test_an_unmapped_target_is_refused if {
	found := violation with input as tree(["riscv64gc-unknown-linux-gnu"], covered)
	some f in found
	f.verdict == "release cover partial"
}

# The could-not-look channel speaks rather than abstaining.
test_an_unparsed_source_is_reported if {
	blind := {"tree": {"documents": {}, "missing": {".github/workflows/release-artifacts.yml": "unparsed"}}}
	found := violation with input as blind
	some f in found
	f.verdict == "workflow read unread"
}
