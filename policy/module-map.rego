# METADATA
# description: |
#   Every crate source module appears in the `mem:core` module map — CLOUD-194,
#   ported from `mise-tasks/module-map-check.sh` under CLOUD-843.
#
#   `rules/rust.md` carries no module tree; it defers outright — "the full
#   per-module map ... is `mem:core`, which is kept current instead of this
#   tree." That makes `mem:core` the single authority on what each module owns,
#   and an authority nothing checks is prose (non-negotiable rule 2). A module
#   added without its row leaves the map silently incomplete and the rule
#   pointing at it untrue. Measured: `severity.rs` (CLOUD-168) landed with no
#   row, past a green gate.
#
#   `memories-check` did not catch it and is not meant to — it gates the graph's
#   EDGES (`mem:` references resolve, names are addressable), a different
#   property that holds fine while the map is missing half its rows.
#
#   THE PREDICATE IS THIS CONSUMER'S. Where a repository keeps its module map,
#   and that it keeps one at all, is a fact about this consumer rather than about
#   the engine — non-negotiable rule 1 — so this is a `policy/*.rego` module and
#   not engine source.
#
#   A MISSING MAP IS COULD-NOT-LOOK, REPORTED ONCE. The shell said so in as many
#   words and the reason survives the port: with the map gone, every module is
#   "absent from the map" and a per-module report would bury the one fact that
#   matters under one line per file. `memories-check` owns the map's existence;
#   this states the dependency and stops.
#
#   THAT ARM CANNOT FIRE TODAY, and it stays anyway. A rule whose declared
#   `line_sources` match nothing is not evaluated at all, and `input.tree.missing`
#   is never populated on the tree surface — `policy/mise-pin-agreement.rego`
#   carries the same measurement for its own could-not-look clause, over an absent
#   `documents` path, an absent `sources` path and an unparseable document, all
#   three exit 0 with no finding (CLOUD-1049). So this clause is correct and the
#   engine is what has to catch up; it carries no `#MUTANT` row for the same
#   reason that module states, because a mutation over an unreachable clause
#   would be reported as a survivor and be right.
#
#   THE SUCCESSOR JUDGES THE CHECKOUT WHERE THE SHELL JUDGED THE INDEX, and that
#   is a stated change rather than an absorbed one (CLOUD-1559). `git ls-files`
#   asked the index; `input.tree.tracked` is a working-tree walk honouring
#   `.gitignore` and is explicitly NOT the index (`facts.rs`, and
#   `policy/lock-complete.rego` records the same trap). Nothing available to a
#   module expresses index membership for a glob: `input.tree.staged` parses each
#   declared path by format and no format owns `.rs`, and `git-status.changed`
#   conflates untracked with modified.
#
#   The consequence, stated because it is a real difference and not a rounding:
#   a NEW module that is written but not yet committed is judged here and was not
#   judged by the shell — the retiring suite pinned that as "an untracked module
#   is not yet the map's problem". The successor is stricter, in the fail-closed
#   direction, and the cost is that a contributor drafting a module is asked for
#   its row before they commit it. That is a decision for CLOUD-1716 to keep or
#   reverse, not one to leave undocumented.
#
#   THE BACKTICKS ARE THE PREDICATE, not decoration. The map names modules in
#   backticks, so a bare prose mention — a sentence ABOUT `severity.rs` — must
#   not read as a row, or the gate passes on the very drift it exists to catch.
#   That is the weakest claim that still catches an absent module while leaving
#   a row's wording free.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.module_map

import rego.v1

rules contains "module-map"

# Where this consumer keeps its map.
map_path := ".serena/memories/core.md"

# The map's text, bound only when it was actually read.
#
# BOUND THROUGH A RULE rather than indexed at each use: every predicate below is
# then undefined without it rather than vacuously clean, which is the difference
# between could-not-look and a pass.
map_lines := lines if {
	lines := input.tree.lines[map_path]
}

# THE COULD-NOT-LOOK ARM. Reported once, and nothing else is reported with it.
violation contains {
	"rule": "module-map",
	"verdict": "memory resolve missing",
	"subjects": [{"path": map_path}],
} if {
	not map_lines
}

# Every tracked crate source module.
#
# `input.tree.tracked` is the successor to the shell's `git ls-files`, and the
# distinction it preserves is the one the retiring suite pinned: an UNTRACKED
# module is not yet the map's problem. The row is owed when the module lands,
# not while it is a draft.
modules contains path if {
	some path in input.tree.tracked
	startswith(path, "crates/")
	contains(path, "/src/")
	endswith(path, ".rs")
}

# The module's own filename, which is what a row names.
basename(path) := parts[count(parts) - 1] if {
	parts := split(path, "/")
}

named(base) if {
	some line in map_lines
	contains(line, sprintf("`%s`", [base]))
}

violation contains {
	"rule": "module-map",
	"verdict": "module place missing",
	"subjects": [{"path": path}],
} if {
	map_lines
	some path in modules
	not named(basename(path))
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves
# `input.tree.tracked` to the tracked set at all — a `with input as` block
# fabricates the very shape the engine may be unable to produce (CLOUD-845), and
# here it would fabricate the tracked/untracked distinction the gate turns on.
# `crates/batten/tests/it/module_map.rs` is that tier.

tree(tracked, lines) := {"tree": {"tracked": tracked, "lines": lines}}

mapped := {".serena/memories/core.md": ["- `main.rs` — the binary boundary."]}

test_a_module_with_a_map_row_is_clean if {
	count(violation) == 0 with input as tree({"crates/demo/src/main.rs"}, mapped)
}

test_a_module_with_no_map_row_is_refused if {
	some v in violation with input as tree({"crates/demo/src/severity.rs"}, mapped)
	v.verdict == "module place missing"
}

test_a_bare_mention_does_not_satisfy_the_row if {
	some v in violation with input as tree(
		{"crates/demo/src/severity.rs"},
		{".serena/memories/core.md": ["Note: severity.rs is described in another memory."]},
	)
	v.verdict == "module place missing"
}

test_a_path_outside_a_crate_source_is_not_a_module if {
	count(violation) == 0 with input as tree({"docs/severity.rs", "crates/demo/tests/severity.rs"}, mapped)
}

#MUTANT-SUITE crates/batten/tests/it/module_map.rs
#MUTANT module-map-row-unread|s@not named(basename(path))@true@|the_repositorys_own_map_is_complete
