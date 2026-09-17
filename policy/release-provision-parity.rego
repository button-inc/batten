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
#MUTANT unverified-may-pass|s@\tnot verified\[target\]@\tfalse@|a_published_target_no_rung_reaches_is_refused
#MUTANT verify-gap-may-be-silent|s@\tnot verify_gap\[target\]@\ttrue@|a_declared_verify_gap_is_silent

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

rules contains "release cover missing"

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
	"rule": "release cover missing",
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
	"rule": "release cover missing",
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
	"rule": "release cover missing",
	"verdict": "release cover partial",
	"subjects": [{"artifact": target}],
} if {
	some target in published
	not platform_of[target]
}

# --- every published target reaches a verification rung ------------------------
#
# CLOUD-364. The sibling property above asks whether a published target can be
# SERVED; this asks whether anything ever LOOKED at it. They are different
# failures with the same subject, which is why they share a module and not an id:
# a finding has to say which coverage is missing.
#
# MEASURED 2026-09-17, and it is the reason this rule exists rather than a
# reading of the workflows: four of the seven published targets had no rung at
# all — not a type-check, not a link, not a run — and one of the four was
# `x86_64-unknown-linux-musl`, which `install.sh` resolves for every Linux
# consumer (113 downloads against 4 for the glibc build on v0.0.159). Every
# artifact is cross-compiled on `ubuntu-latest`, so nothing CI executes is ever
# what ships; the rungs below are what stands between a target and shipping
# unlooked-at.
#
# READ INLINE for the reason the header gives: `mise.toml` declares `[tasks.deny]`,
# and a top-level rule whose value carries a `deny` key at any depth silences the
# whole module.

# The triples `cross-check` type-checks, read from the task body rather than
# restated. A substring test and not a parse: the body is a shell loop, and a
# second parser for it would be a second authority on a list mise owns.
checked contains target if {
	some target, _ in platform_of
	contains(object.get(input.tree.documents["mise.toml"].tasks, ["cross-check", "run"], ""), target)
}

# The triples `darwin-link` links. A real link is strictly stronger than a check,
# which is why the Darwin pair lives there and not in the loop above.
linked contains target if {
	some target in input.tree.documents[".github/workflows/rust.yml"].jobs["darwin-link"].strategy.matrix.target
}

# The host triple every ubuntu job executes natively. Declared rather than
# derived: `runs-on: ubuntu-latest` names an image, not a target triple, and
# inferring one from it would be this file guessing at GitHub's fleet.
native := {"x86_64-unknown-linux-gnu"}

# THE aarch64 PAIR, AND THE GAP IS DECLARED BECAUSE IT IS REAL. `cargo check`
# needs no target linker, but it does run build scripts, and `blake3` shells out
# to `cc` for its NEON path on any aarch64 target — `failed to find tool
# "aarch64-linux-gnu-gcc"`, and the musl twin identically. So the constraint is
# the architecture rather than the libc. `release-artifacts.yml` builds both under
# `build-tool: cross`, which supplies a toolchain in a container; the verification
# path has no equivalent and pinning one is its own change.
#
# A DECLARED GAP IS NOT COVERAGE, the same way the platform gap above is not: the
# target still ships unverified. What the declaration buys is that it ships
# KNOWN-unverified, which is the whole of CLOUD-364's no-silent-caps rule.
verify_gap := {
	"aarch64-unknown-linux-gnu",
	"aarch64-unknown-linux-musl",
}

verified contains target if checked[target]

verified contains target if linked[target]

verified contains target if native[target]

# GUARDED ON THE RUNG SURFACE, and the guard is the difference between a verdict
# and a guess. A tree with no `cross-check` task is not running this gate at all,
# so "which targets does it cover" is a question this rule cannot answer — and
# answering it as *uncovered* would report a could-not-look as a decision, which
# is the class this repository exists to refuse and which the sibling rule's own
# `workflow read unread` arm keeps separate.
#
# Measured here rather than reasoned: without it this clause fired over the
# provision fixtures above, which declare no task surface at all, and reported
# every target in them as unverified.
governed if input.tree.documents["mise.toml"].tasks["cross-check"]

violation contains {
	"rule": "release cover missing",
	"verdict": "release check absent",
	"subjects": [{"artifact": target}],
} if {
	governed
	some target in published
	not verified[target]
	not verify_gap[target]
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
	f.rule == "release cover missing"
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

# --- the verification-rung predicate's own tests -------------------------------

# A tree carrying the three rung surfaces. Separate from `tree()` above because
# that fixture answers the provision question and this one answers coverage; one
# fixture serving both would make each case's subject ambiguous.
rungs(targets, cross_run, darwin_targets) := {"tree": {
	"documents": {
		".github/workflows/release-artifacts.yml": {"jobs": {"dist": {"strategy": {"matrix": {"include": [{"target": t} | some t in targets]}}}}},
		".github/workflows/rust.yml": {"jobs": {"darwin-link": {"strategy": {"matrix": {"target": darwin_targets}}}}},
		"mise.toml": {"tasks": {"cross-check": {"run": cross_run}}},
		"batten.toml": {"provision": [{"name": "scanner", "platforms": {
			"linux-x86_64": {"url": "u"},
			"linux-aarch64": {"url": "u"},
			"macos-x86_64": {"url": "u"},
			"macos-aarch64": {"url": "u"},
			"windows-x86_64": {"url": "u"},
		}}]},
	},
	"missing": {},
}}

# THE CASE THE RULE EXISTS FOR: a target published with no rung anywhere.
test_a_published_target_no_rung_reaches_is_refused if {
	found := violation with input as rungs(["x86_64-pc-windows-gnu"], "for t in nothing; do", [])
	some f in found
	f.verdict == "release check absent"
	some sub in f.subjects
	sub.artifact == "x86_64-pc-windows-gnu"
}

# Each rung satisfies on its own, which is what keeps the rule from demanding all
# three of every target.
test_a_type_checked_target_is_clean if {
	found := violation with input as rungs(["x86_64-pc-windows-gnu"], "for t in x86_64-pc-windows-gnu; do", [])
	every f in found {
		f.verdict != "release check absent"
	}
}

test_a_linked_target_is_clean if {
	found := violation with input as rungs(["x86_64-apple-darwin"], "for t in nothing; do", ["x86_64-apple-darwin"])
	every f in found {
		f.verdict != "release check absent"
	}
}

# The host triple needs no workflow to name it: every ubuntu job runs it.
test_the_native_target_is_clean if {
	found := violation with input as rungs(["x86_64-unknown-linux-gnu"], "for t in nothing; do", [])
	every f in found {
		f.verdict != "release check absent"
	}
}

# A DECLARED GAP IS SILENT, and this is the case that says so — without it the
# `verify_gap` set would be unreachable and the aarch64 pair would red forever.
test_a_declared_verify_gap_is_silent if {
	found := violation with input as rungs(["aarch64-unknown-linux-musl"], "for t in nothing; do", [])
	every f in found {
		f.verdict != "release check absent"
	}
}

# THE ANTI-VACUITY TERM. Every case above is about one target; none of them
# notices a rung surface that has gone missing entirely. A `cross-check` whose
# body no longer names the triple it used to must red rather than read as covered
# by some other rung.
test_a_rung_that_stops_naming_its_target_is_refused if {
	found := violation with input as rungs(["x86_64-unknown-linux-musl"], "for t in x86_64-pc-windows-gnu; do", [])
	some f in found
	f.verdict == "release check absent"
	some sub in f.subjects
	sub.artifact == "x86_64-unknown-linux-musl"
}

# NOT-APPLICABLE IS NOT A VERDICT, and this is the case that keeps the guard from
# being a way to switch the rule off: a tree that declares no `cross-check` task
# is not answering this question, which is what the provision fixtures above are.
test_a_tree_with_no_cross_check_task_is_not_this_rules_business if {
	found := violation with input as tree(["x86_64-pc-windows-gnu"], covered)
	every f in found {
		f.verdict != "release check absent"
	}
}
