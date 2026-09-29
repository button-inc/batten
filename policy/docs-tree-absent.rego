# No committed `docs/` tree (AGENTS.md, non-negotiable rule 7), retired off the
# `no-docs-tree` task body under CLOUD-1991.
#
# Research deliverables and evidence notes attach to the tracker row they back;
# a repository `docs/` folder is a second home for them that nothing reads and
# everything forgets. The predecessor was `git ls-files 'docs/*' 'docs/**' |
# head -n1` in shell, refusing when it printed anything.
#
# ─── WHAT IT READS: THE INDEX, NOT THE WALK ─────────────────────────────────
#
# `input.tree["git-index"]["docs"]` is `git ls-files -s -- docs`, entry for
# entry, which is the predecessor's own question. The working-tree walk
# (`input.tree.tracked`) is not: it honours `.gitignore` and ignores the index,
# so it would miss a force-added file and name an untracked one. The spec is
# `docs` rather than the predecessor's two globs because a pathspec already
# reaches everything beneath the directory — and it also reaches a FILE named
# `docs`, which is a docs tree by any reading.
#
# ─── COULD-NOT-LOOK IS SILENT, AS IT WAS ─────────────────────────────────────
#
# The fact is `null` when the index could not be read. The predecessor's
# `git ls-files` failing printed nothing and passed; this keeps that reading
# rather than widening it, and says so rather than letting a reader infer a
# stricter gate than there is.
#
#MUTANT docs-tree-admitted|s@^\tcount(docs.entries) > 0$@\tfalse@|a_tracked_docs_file_is_refused
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
package batten.docs_tree_absent

import rego.v1

rules contains "prose place refused"

# The pathspec the row's `index` column declares. The fact is keyed by the spec
# as written, so the two spellings must agree.
spec := "docs"

# Bound only for an object, so every arm below is UNDEFINED rather than
# vacuously clean when the index could not be read.
docs := fact if {
	fact := input.tree["git-index"][spec]
	is_object(fact)
}

violation contains {
	"rule": "prose place refused",
	"verdict": "prose place refused",
	"subjects": [{"path": first}, {"count": count(docs.entries)}],
} if {
	count(docs.entries) > 0
	first := min({entry.path | some entry in docs.entries})
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE over a fabricated input. That the ENGINE fills
# `git-index` for the declared spec is `crates/batten/tests/it/tracked_absent.rs`'s
# to show, over the compiled binary (CLOUD-845).

index(entries) := {"tree": {"git-index": {"docs": {"entries": entries, "diverged": [], "untracked": []}}}}

entry(path) := {"path": path, "mode": "100644", "oid": "0000000000000000000000000000000000000000", "stage": 0}

test_a_tracked_docs_file_is_refused if {
	found := violation with input as index([entry("docs/notes.md")])
	count(found) == 1
	some finding in found
	finding.subjects[0].path == "docs/notes.md"
}

test_the_pointer_is_the_first_path_and_a_count if {
	found := violation with input as index([entry("docs/z.md"), entry("docs/a.md")])
	some finding in found
	finding.subjects == [{"path": "docs/a.md"}, {"count": 2}]
}

test_an_empty_docs_spec_is_clean if {
	count(violation) == 0 with input as index([])
}

test_an_unread_index_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"git-index": {"docs": null}}}
}

test_no_index_fact_at_all_decides_nothing if {
	count(violation) == 0 with input as {"tree": {}}
}
