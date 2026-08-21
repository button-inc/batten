#!/usr/bin/env bats
# subject: mise-tasks/evaluator-closure-check
# The closure half of CLOUD-831's pin, and the reason it takes a metadata
# fixture rather than only running against the real tree.
#
# The live graph is clean by construction — that is what the gate exists to keep
# true — so a suite that could only ask the real tree would assert a pass and
# never a refusal, which is exactly the coverage-theatre shape CLOUD-418 names.
# `BATTEN_EVALUATOR_METADATA` substitutes a recorded graph, and the cases below
# are the four directions this predicate has to separate. Three of them cannot be
# produced by editing the real manifest at all.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/evaluator-closure-check"
	META="$BATS_TEST_TMPDIR/metadata.json"
}

# A `cargo metadata` document carrying just enough shape for the walk: a
# workspace member, the evaluator, and whatever else a case names.
#
# `$1` is the JSON body of `regorus`'s dependency list, `$2` the extra packages
# and nodes. Written as a here-doc rather than assembled with jq so a reader can
# see the whole graph a case asserts over.
metadata() {
	cat >"$META"
}

@test "the repo's real graph is clean today" {
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"none of the regorus closure"* ]]
}

@test "an IO crate reachable from the evaluator is refused at exit 2" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {},
		     "dependencies": [{"name": "regorus"}]},
		    {"id": "regorus", "name": "regorus", "features": {},
		     "dependencies": [{"name": "reqwest"}]},
		    {"id": "reqwest", "name": "reqwest", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": [], "deps": [{"pkg": "reqwest", "dep_kinds": [{"kind": null}]}]},
		    {"id": "reqwest", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"reqwest"* ]]
}

# THE LOAD-BEARING CASE. The obvious spelling of this predicate walks from the
# workspace members, and on the real tree that finds `jsonschema` and `globset` —
# direct dependencies of `batten` itself, entering by paths that have nothing to
# do with the evaluator. It would deny on `main` forever. This fixture is that
# exact topology, and the gate must be SILENT on it.
@test "an IO crate the workspace depends on directly, but the evaluator does not, is not the evaluator's" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {},
		     "dependencies": [{"name": "regorus"}, {"name": "jsonschema"}, {"name": "globset"}]},
		    {"id": "regorus", "name": "regorus", "features": {}, "dependencies": []},
		    {"id": "jsonschema", "name": "jsonschema", "features": {}, "dependencies": []},
		    {"id": "globset", "name": "globset", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [
		      {"pkg": "regorus", "dep_kinds": [{"kind": null}]},
		      {"pkg": "jsonschema", "dep_kinds": [{"kind": null}]},
		      {"pkg": "globset", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": [], "deps": []},
		    {"id": "jsonschema", "features": [], "deps": []},
		    {"id": "globset", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 0 ]
}

# The activation filter, which is `macos-link-check`'s `defmt` lesson applied
# here: an optional dependency nobody enabled is in the resolve and is not in the
# build, and a gate that fails on a crate the compiler never sees is not
# measuring what it names.
@test "an unactivated optional IO dependency of the evaluator is not reported" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {},
		     "dependencies": [{"name": "regorus"}]},
		    {"id": "regorus", "name": "regorus", "features": {"http": ["dep:reqwest"]},
		     "dependencies": [{"name": "reqwest", "optional": true}]},
		    {"id": "reqwest", "name": "reqwest", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": ["std"], "deps": [{"pkg": "reqwest", "dep_kinds": [{"kind": null}]}]},
		    {"id": "reqwest", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 0 ]
}

# The other direction of the same filter: enable the feature and the same graph
# must refuse. Without this case the one above passes on a gate that reports
# nothing at all.
@test "the same optional dependency, activated, IS reported" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {},
		     "dependencies": [{"name": "regorus"}]},
		    {"id": "regorus", "name": "regorus", "features": {"http": ["dep:reqwest"]},
		     "dependencies": [{"name": "reqwest", "optional": true}]},
		    {"id": "reqwest", "name": "reqwest", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": ["std", "http"], "deps": [{"pkg": "reqwest", "dep_kinds": [{"kind": null}]}]},
		    {"id": "reqwest", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"reqwest"* ]]
}

# Could-not-look, never a pass. If the evaluator is not in the graph the question
# was not asked, and reporting "nothing found" there is CLOUD-251's vacuous pass
# in the one place it would be least visible.
@test "no evaluator node at all is could-not-look, not a clean bill" {
	metadata <<-'JSON'
		{
		  "packages": [{"id": "batten", "name": "batten", "features": {}, "dependencies": []}],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [{"id": "batten", "features": [], "deps": []}]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not be walked"* ]]
}

# Non-negotiable rule 4. The refusal names the crate and nothing else — no
# version chain, no path through the graph, no dependency tree.
@test "the refusal is pointer-only: the crate name, never the path that reached it" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {}, "dependencies": [{"name": "regorus"}]},
		    {"id": "regorus", "name": "regorus", "features": {}, "dependencies": [{"name": "secret-middle"}]},
		    {"id": "secret-middle", "name": "secret-middle", "features": {}, "dependencies": [{"name": "ring"}]},
		    {"id": "ring", "name": "ring", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": [], "deps": [{"pkg": "secret-middle", "dep_kinds": [{"kind": null}]}]},
		    {"id": "secret-middle", "features": [], "deps": [{"pkg": "ring", "dep_kinds": [{"kind": null}]}]},
		    {"id": "ring", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"ring"* ]]
	[[ "$output" != *"secret-middle"* ]]
}

# A dev-dependency of a DEPENDENCY is never built, so it is not in the closure a
# policy module could reach. (A workspace member's dev-dependency is built — the
# test binaries link — but that is the members' walk, not the evaluator's.)
@test "a dev-dependency of the evaluator is not in the built closure" {
	metadata <<-'JSON'
		{
		  "packages": [
		    {"id": "batten", "name": "batten", "features": {}, "dependencies": [{"name": "regorus"}]},
		    {"id": "regorus", "name": "regorus", "features": {}, "dependencies": [{"name": "reqwest"}]},
		    {"id": "reqwest", "name": "reqwest", "features": {}, "dependencies": []}
		  ],
		  "workspace_members": ["batten"],
		  "resolve": {"nodes": [
		    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
		    {"id": "regorus", "features": [], "deps": [{"pkg": "reqwest", "dep_kinds": [{"kind": "dev"}]}]},
		    {"id": "reqwest", "features": [], "deps": []}
		  ]}
		}
	JSON
	BATTEN_EVALUATOR_METADATA="$META" run "$GATE"
	[ "$status" -eq 0 ]
}
