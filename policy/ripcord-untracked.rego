# The break-glass sentinel is never committed (CLOUD-1847), retired off the
# `no-armed-ripcord` task body under CLOUD-1991.
#
# `.batten-ripcord` opens the repair floor over a config that loads and denies —
# the right answer for one operator's container that would otherwise be
# abandoned, and the wrong thing entirely to hand to every clone. `.gitignore`
# carries the name, so reaching this takes a deliberate `git add -f`, which is
# exactly the case a gate is for.
#
# ─── THE INDEX, WHOLE, WHATEVER COMMIT ADDED IT ─────────────────────────────
#
# `input.tree["git-index"][".batten-ripcord"]` is `git ls-files -s --
# .batten-ripcord`, the predecessor's own question. It refuses a tracked sentinel
# however long ago it was added; a delta over a base would let one persist
# unreported for every commit that did not touch it (CLOUD-224's reason, which the
# predecessor's header gave for being glob-less).
#
# The working-tree walk cannot stand in for it: it honours `.gitignore`, and the
# sentinel is ignored by name, so a walk would never see the one file this exists
# to find.
#
#MUTANT ripcord-admitted|s@^\tcount(sentinel.entries) > 0$@\tfalse@|a_force_added_sentinel_is_refused
#
#MUTANT-SUITE crates/batten/tests/it/tracked_absent.rs

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ripcord_untracked

import rego.v1

rules contains "path ship refused"

# The pathspec the row's `index` column declares, spelled identically.
spec := ".batten-ripcord"

sentinel := fact if {
	fact := input.tree["git-index"][spec]
	is_object(fact)
}

violation contains {
	"rule": "path ship refused",
	"verdict": "path ship refused",
	"subjects": [{"path": spec}],
} if {
	count(sentinel.entries) > 0
}

# --- the load-time tier ------------------------------------------------------

index(entries) := {"tree": {"git-index": {".batten-ripcord": {"entries": entries, "diverged": [], "untracked": []}}}}

test_a_force_added_sentinel_is_refused if {
	found := violation with input as index([{"path": ".batten-ripcord", "mode": "100644", "oid": "0000000000000000000000000000000000000000", "stage": 0}])
	count(found) == 1
	some finding in found
	finding.subjects == [{"path": ".batten-ripcord"}]
}

# An ARMED but untracked sentinel is the operator's own business: it is in the
# working tree, ignored, and ships nowhere.
test_an_armed_untracked_sentinel_is_clean if {
	count(violation) == 0 with input as {"tree": {"git-index": {".batten-ripcord": {"entries": [], "diverged": [], "untracked": []}}}}
}

test_an_unread_index_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"git-index": {".batten-ripcord": null}}}
}
