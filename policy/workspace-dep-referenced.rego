# Every `[workspace.dependencies]` key is referenced by a member (CLOUD-882).
#
# `[workspace.dependencies]` FIXES A VERSION; it does not add a dependency. A
# member must name the key with `<key>.workspace = true`. So an entry no member
# references resolves to nothing, and every gate that reads the RESOLVED graph
# reports green about a tree that does not contain it.
#
# MEASURED, and the measurement is why this is a gate rather than a note.
# `orphan-probe = "=9.9.9"` -- a crate that does not exist, at a version that
# does not exist -- added to the root table alone produced four greens:
# `cargo metadata` resolved clean with the crate absent from the package list,
# `macos-link-check` exited 0, and `deny` reported advisories, bans, licenses and
# sources all ok. Cargo does not complain either: an unreferenced entry is legal
# and inert by design, which is exactly why nothing downstream can see it.
#
# It is self-concealing in the worst direction. Adding a dependency is precisely
# when somebody runs those gates deliberately, so a typo'd or half-finished
# declaration makes every one of them agree, confidently, about nothing.
#
# NOT BASH, and that is a decision with a scar behind it. A line pass would have
# to associate a key with its `[table]` and correlate across manifests, which is
# the shape that took four review rounds on `attribution-check` and produced
# nothing durable (CLOUD-873, canceled). Two parsed documents answer it in one
# walk, which is what a `policy` row is for.
#
# WHAT IT DOES NOT REPORT. A member naming a key the root does not declare is
# cargo's own hard error, and re-reporting it here would be a second voice on a
# question already answered loudly. This rule is one-directional on purpose.
#
# THE UNREADABLE-MANIFEST CLAUSE IS NOT OPTIONAL, and it is the same class this
# row is about. A declared path that failed to parse lands in `input.tree.missing`
# rather than in `documents`; without the clause below it is simply absent from
# the walk and the module reports green over a manifest it never read.
#MUTANT-EXEMPT CLOUD-931|no `tests/workspace-dep-referenced.bats` exists: `mutant` resolves a gate's suite as `tests/$gate.bats`, so without one there is no named case a mutation could turn red. `batten policy test` IS wired as of CLOUD-931, but that is the load-time tier and a `with input as` case is not what the mutation runner drives

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`, and an unbound
#   module type checks as `Any` -- silently unchecked (CLOUD-876).
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`:
#   OPA parses the whole contiguous block that starts the annotation, so prose
#   after it reaches the YAML parser and the module fails to load.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.workspace_dep_referenced

import rego.v1

rules contains "workspace-dep-referenced"

# The root manifest's declared keys.
declared contains key if {
	some key, _ in input.tree.documents["Cargo.toml"].workspace.dependencies
}

# Every key any member references with `workspace = true`.
#
# THE THREE TABLES AND THEIR `target.*` FORMS, because a dependency declared
# under `[target.'cfg(unix)'.dependencies]` is as referenced as any other and a
# rule that missed it would report a false orphan — worse than the silence it
# replaces, since a false red gets the gate switched off.
referenced contains key if {
	some path, doc in input.tree.documents
	path != "Cargo.toml"
	some table in ["dependencies", "dev-dependencies", "build-dependencies"]
	some key, value in doc[table]
	value.workspace == true
}

referenced contains key if {
	some path, doc in input.tree.documents
	path != "Cargo.toml"
	some _, cfg in doc.target
	some table in ["dependencies", "dev-dependencies", "build-dependencies"]
	some key, value in cfg[table]
	value.workspace == true
}

# THE ORPHAN. Pointer-only: the KEY and the manifest that declares it, never a
# line of either file. A document finding carries no line number by construction,
# so the message is where the pointer lives.
violation contains {
	"rule": "workspace-dep-referenced",
	"verdict": "V-WORKSPACE-DEP-ORPHANED",
	"subjects": [{"artifact": key}],
} if {
	some key in declared
	not referenced[key]
}

# COULD NOT LOOK, NEVER A SILENT PASS. A manifest the engine could not parse is
# in `missing`, and without this the walk above simply does not see it.
violation contains {
	"rule": "workspace-dep-referenced",
	"verdict": "V-MANIFEST-UNPARSED",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	endswith(path, "Cargo.toml")
}

# ANTI-VACUITY. A run that judged no root table decided nothing, and reporting
# clean would be indistinguishable from a workspace with no orphans. This is the
# CLOUD-251 shape the whole row is an instance of, closed on the module's own
# input rather than assumed away.
violation contains {
	"rule": "workspace-dep-referenced",
	"verdict": "V-WORKSPACE-TABLE-ABSENT",
} if {
	count(declared) == 0
}

# --- cases ---------------------------------------------------------------
#
# The discriminating PAIR is the point (CLOUD-418): the same fixture with and
# without a member reference must land on opposite verdicts. A red-only case
# would pass over a rule that refused everything.

test_an_orphaned_key_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"orphan-probe": "=9.9.9"}}},
			"crates/m/Cargo.toml": {"dependencies": {}},
		},
		"missing": [],
	}}
	count(found) == 1
}

test_a_referenced_key_is_clean if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"serde": "1"}}},
			"crates/m/Cargo.toml": {"dependencies": {"serde": {"workspace": true}}},
		},
		"missing": [],
	}}
	count(found) == 0
}

# `workspace = false` is a member declining the workspace version, which is NOT
# a reference — the key still resolves to nothing. A rule keyed on the presence
# of the field rather than its value would call this clean.
test_workspace_false_is_not_a_reference if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"serde": "1"}}},
			"crates/m/Cargo.toml": {"dependencies": {"serde": {"workspace": false}}},
		},
		"missing": [],
	}}
	count(found) == 1
}

# A dev-dependency counts, and so does a target-conditional one. Both are real
# shapes in this workspace, and a rule that missed either would report a FALSE
# orphan — worse than silence, because a false red gets the gate switched off.
test_a_dev_dependency_counts if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"insta": "1"}}},
			"crates/m/Cargo.toml": {"dev-dependencies": {"insta": {"workspace": true}}},
		},
		"missing": [],
	}}
	count(found) == 0
}

test_a_target_conditional_dependency_counts if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"nix": "0.29"}}},
			"crates/m/Cargo.toml": {"target": {"cfg(unix)": {"dependencies": {"nix": {"workspace": true}}}}},
		},
		"missing": [],
	}}
	count(found) == 0
}

# CARGO'S ERROR, NOT THIS GATE'S. A member naming a key the root does not declare
# is a hard cargo failure already; a second voice here would be noise on a
# question answered loudly elsewhere.
test_a_member_reference_the_root_lacks_is_not_reported if {
	found := violation with input as {"tree": {
		"documents": {
			"Cargo.toml": {"workspace": {"dependencies": {"serde": "1"}}},
			"crates/m/Cargo.toml": {"dependencies": {
				"serde": {"workspace": true},
				"undeclared": {"workspace": true},
			}},
		},
		"missing": [],
	}}
	count(found) == 0
}

# THE FALSE-GREEN SHAPE THIS ROW IS ITSELF AN INSTANCE OF. An unreadable member
# manifest must be loud: its references were never counted, so an orphan cannot
# be ruled out.
test_an_unparseable_manifest_is_loud if {
	found := violation with input as {"tree": {
		"documents": {"Cargo.toml": {"workspace": {"dependencies": {"serde": "1"}}}},
		"missing": ["crates/m/Cargo.toml"],
	}}
	count(found) == 2
}

test_no_root_table_decides_nothing_and_says_so if {
	found := violation with input as {"tree": {"documents": {}, "missing": []}}
	count(found) == 1
}
