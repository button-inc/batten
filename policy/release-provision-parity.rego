# CLOUD-1431. We publish a binary for a platform on which one of our own rule
# kinds cannot run, and nothing in the tree relates the two lists.
#
# THE DEFECT, MEASURED. `release-artifacts.yml` publishes seven targets, three of
# them arm64. The `secrets` rule kind resolves its scanner from the single
# `[[provision]]` row, whose platform table is `linux-x86_64`, `macos-x86_64` and
# `macos-aarch64`. So a consumer who installs the `aarch64-unknown-linux-gnu`
# release we ship, declares a `secrets` rule and runs `batten enforce` gets:
#
#   provision ripsecrets: no artifact for linux-aarch64;
#           the entry pins linux-x86_64, macos-aarch64, macos-x86_64
#
# Found here as a red required check rather than as a consumer report, on job
# 100903936005, because moving `batten-check` to `ubuntu-24.04-arm` made this
# repository the first arm64 consumer of its own engine.
#
# THE RUNTIME IS ALREADY RIGHT, AND THAT IS WHY THIS IS A CONFIG GATE.
# `provision.rs` says it in as many words: "Never a silent skip: an entry that
# cannot be installed here is a manifest this host cannot satisfy, and reporting
# it as fresh would let a gate depending on the tool pass without the tool." Exit
# 1 is the correct direction. What is missing is AUTHORING-TIME detection, so the
# pairing is decided on the change that introduces it instead of on somebody's
# arm runner months later.
#
# WHY NO STANDING GATE CAUGHT IT, which is the generalisable half. `lock-complete`
# requires every `[tools]` entry to install on three mandatory platforms,
# linux-arm64 among them — which is why CLOUD-1416 concluded the tool surface was
# already proven on this architecture, a sound conclusion for the surface it
# names. `ripsecrets` is not on that surface: it is the only `[[provision]]` row
# in the config, and `[[provision]]` carries no platform-completeness requirement
# of any kind. Two pinned-tool surfaces, one gated for arm64 and one not, and the
# ungated one holding exactly one entry is why nobody noticed the asymmetry.
#
# A CONSUMER MODULE RATHER THAN A PRESET OR THE CORE. The predicate names this
# repository's facts — which workflow publishes releases, which platform keys its
# provision rows carry — so `.claude/rules/toolchain.md`'s default applies and a
# preset would need those pulled out into config a preset cannot read anyway. It
# needs no engine change: both lists are committed bytes.
#MUTANT-SUITE crates/batten/tests/it/release_provision_parity.rs
#MUTANT gap-may-go-undeclared|s@not declared_gap\[key\]@false@|an_undeclared_platform_gap_is_refused
#MUTANT musl-may-not-map|s@"aarch64-unknown-linux-musl": "linux-aarch64",@@|a_musl_triple_maps_to_the_same_platform_key_as_gnu

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

# THE RUST TRIPLE A WORKFLOW PUBLISHES IS NOT THE PLATFORM KEY A PROVISION ROW
# CARRIES, and the mapping is the whole of what this rule has to get right.
#
# `provision.rs`'s `platform_key()` builds `<os>-<arch>`, so the libc flavour is
# deliberately absent: `-gnu` and `-musl` are the same platform to a downloaded
# binary's URL table, and mapping them to one key is what stops a musl target
# reading as an uncovered platform when its gnu sibling is pinned.
#
# A STATIC OBJECT rather than a function with a definition per arm: regorus
# reads a multi-arm function as a multi-value rule and the module would not load.
# A target this map does not name is could-not-look below, never a pass.
platform_of := {
	"x86_64-unknown-linux-gnu": "linux-x86_64",
	"aarch64-unknown-linux-gnu": "linux-aarch64",
	"x86_64-unknown-linux-musl": "linux-x86_64",
	"aarch64-unknown-linux-musl": "linux-aarch64",
	"x86_64-apple-darwin": "macos-x86_64",
	"aarch64-apple-darwin": "macos-aarch64",
	"x86_64-pc-windows-gnu": "windows-x86_64",
}

# THE DECLARED GAPS, AND EACH ONE IS A STATEMENT ABOUT UPSTREAM RATHER THAN A
# SUPPRESSION.
#
# A gap earns a row here only when the artifact does not exist to pin. Both of
# these were verified against the scanner's own releases, not inferred from the
# refusal: v0.1.11 publishes exactly `aarch64-apple-darwin`, `x86_64-apple-darwin`
# and `x86_64-unknown-linux-gnu` — three binaries, and every tag from v0.1.2
# ships the same three. `no-source-built-tool` forbids compiling one.
#
# WINDOWS WAS THE SECOND INSTANCE AND NOBODY HAD NOTICED IT. CLOUD-1431 was
# written about arm64 because an arm64 runner surfaced it; building this map is
# what showed `x86_64-pc-windows-gnu` has been in exactly the same state for its
# whole life, with no runner to reveal it. That is the argument for the gate
# rather than for the one fix: a list nobody compares drifts in silence.
#
# WHAT A DECLARED GAP COSTS A CONSUMER, stated so the row is not read as making
# the platform work: `batten enforce` on that platform, with a `secrets` rule
# declared, exits 1 naming the missing key. Fail-closed and loud, which is
# `provision.rs`'s decision and the right one — but it is a refusal, not
# scanning. The durable answer is a scanner that ships for these platforms
# (CLOUD-59 owns that evaluation and its licence question); until then the gate's
# job is to keep the gap visible instead of emergent.
declared_gap := {
	"linux-aarch64",
	"windows-x86_64",
}

# The release workflow's target matrix, read inline.
#
# INLINE RATHER THAN BOUND TO A TOP-LEVEL RULE, and this is not style: measured
# on the compiled engine, a top-level rule whose VALUE carries a `deny` key at
# any depth silences the whole module — every predicate, including one whose body
# is `true`. `policy/ci-parity.rego` was dead over this repository's own tree for
# as long as it bound `mise.toml`, which declares `[tasks.deny]`. `batten.toml`
# is a policy authority full of the word, so binding either document is the one
# mistake that makes this file look clean and decide nothing.
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
# abstention is not a finding and nobody reads it. `.claude/rules/policy-modules.md`
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
