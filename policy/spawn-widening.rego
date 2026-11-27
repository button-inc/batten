# A SPAWN IS AN INVENTORY ROW, AND THE INVENTORY MAY NOT BE SELF-SERVICE
# (CLOUD-1338).
#
# `.claude/rules/rust.md` says a new spawn "is not forbidden — it is an inventory
# row, and the annotation is where you write down whether it stays and why", and
# `policy/spawn-adapters.rego` gates WHERE one may appear. Both are sound and
# neither is a brake, because both are answered by the author of the spawn, in
# the same commit, with no reader: the annotation's `reason` is a string nothing
# checks, and the placement is a word added to a Rego set.
#
# MEASURED ON THE BRANCH THAT PROMPTED THIS ROW, and it is the worst possible
# case rather than a hypothetical: a branch whose entire stated subject was
# RETIRING SHELL added five `#[expect(clippy::disallowed_types)]` spawns and
# widened `spawn-adapters`' placement table twice. Every sensor in the repository
# stayed green. Every one of the five reasons said the same thing — *"this crate
# carries no HTTP client that resolves a forge credential, so the forge's own
# client IS the call"* — and that sentence was FALSE: `crates/batten/src/fetch.rs`
# is a vendored hyper client, and `lease.rs` was already reading `GH_TOKEN`
# through it eighty lines from one of the five.
#
# So this rule decides the one thing neither of its siblings can: whether the
# DIFF widens the inventory. It reads `input.tree["base-delta"]`, which is what
# lets a module decide a CHANGE rather than a state (CLOUD-1059), and it refuses
# an added placement.
#
# THE ESCAPE CLAUSE IS RETIRED (CLOUD-2778). It compared a file's added lines as
# a set, so a second escape whose lint line repeated one already there read as
# no change, and the counted repair that followed it was still text. `spawn
# count ahead`, a `counts = "lint_escapes"` ratchet over every package's source,
# counts the escapes off the parsed tree against `origin/main`, so this module
# keeps the placement clause and the could-not-look arms.
#
# FAIL CLOSED, WITH NO `bypass_env` AND NO OVERRIDE ROUTE. That is deliberate and
# it follows `shell edit refused`'s precedent, which declares one route with
# neither: the answer to this refusal is not a token to spend, it is that the
# change has the wrong shape. A spawn that genuinely belongs is a decision for a
# groomed row and a human, not an annotation an agent writes about its own work.
#
# WHAT IT DOES NOT CLAIM. It cannot tell a justified spawn from an unjustified
# one — that is a judgement, and non-negotiable rule 3 forbids a gate resolving
# to one. It decides a byte question: did this change add a placement admitting
# a spawn. That is answerable from the delta, and was unanswered until now.
#
#MUTANT placement-widening-unread|s@patterns\[placement_pattern\]@patterns["spawn-placement-unread"]@|an_added_spawn_placement_is_refused
#MUTANT-SUITE crates/batten/tests/it/spawn_widening.rs

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.spawn_widening

import rego.v1

rules contains "spawn add other"

# `input.tree["base-delta"]` is NULL when the base rev did not resolve, and
# `null` is not `undefined` — `not input.tree["base-delta"]` would be FALSE for
# it, which is the slip CLOUD-701's review caught in `spawn-adapters` itself. So
# the delta is bound through a rule that holds only for an object, and every
# predicate below is undefined without it rather than vacuously clean.
delta := d if {
	d = input.tree["base-delta"]
	is_object(d)
}

# THE PATTERNS ARE `[[pattern]]` ROWS, never inline regexes. One concept, one
# spelling, refused at load rather than duplicated at leisure —
# `.claude/rules/policy-modules.md` is the authority and the reason is measured
# there: one concept was spelled 19 different ways across 17 shell programs
# before the registry existed.
placement_pattern := "spawn-placement-entry"

# The module whose set says which files may spawn. Named once: it is the SUBJECT
# of the second clause, and a second spelling is a second answer to "which file
# holds the placements".
placements_module := "policy/spawn-adapters.rego"

# Lines this change ADDED to `path`.
#
# `base-lines` carries the base side of every EDITED path — `git.rs` states the
# bound on the field itself: not `added` (there is no base side) and not
# `deleted` (the head side is gone). So an added FILE has no base to subtract and
# every one of its lines is new, which is the arm below.
#
# A SET DIFFERENCE, and its one bound is stated rather than discovered: a line
# that already appeared elsewhere in the base file is not counted as added, so
# moving an existing escape from one function to another reads as no change.
# That is the correct direction for this rule — the inventory did not grow — and
# it is why the second clause counts MEMBERS rather than lines.
# THE BASE IS BOUND BEFORE IT IS WALKED, and that is a correctness clause rather
# than a style: a comprehension over an UNDEFINED collection yields the EMPTY SET
# rather than undefined, so writing `{line | some line in delta["base-lines"][path]}`
# directly makes an unchanged file look like a file whose every line is new.
# Measured here: 81 of 81 engine modules refused on one run, which is a gate that
# fires on everything and therefore gates nothing.
#
# Binding it first makes this arm UNDEFINED for a path the delta carries no base
# for, which is what leaves the added-file arm below to answer and leaves an
# unchanged file answered by neither.
added_lines(path) := added if {
	base_lines = delta["base-lines"][path]
	base := {line | some line in base_lines}
	added := {line |
		some line in input.tree.lines[path]
		not base[line]
	}
}

# AN ADDED FILE HAS NO BASE TO SUBTRACT, so every line in it is new.
#
# The membership test is spelled over a comprehension rather than `some path in
# delta.added`, because `path` is the rule's own argument and Rego reads a `some`
# binding it as a redefinition — measured here as `var path used before
# definition`, which faults the whole module at load rather than at evaluation.
added_lines(path) := added if {
	count([p | some p in delta.added; p == path]) > 0
	not delta["base-lines"][path]
	added := {line | some line in input.tree.lines[path]}
}

# ENGINE SOURCE, every package's: `crates/<crate>/src/**` (#1276), read from the
# path rather than a list of crates. Only the could-not-look arm below reads it
# now that the escape clause is retired (CLOUD-2778); `tests/**` is excluded by
# construction.
engine_source(path) if {
	parts := split(path, "/")
	count(parts) > 3
	parts[0] == "crates"
	parts[2] == "src"
	endswith(path, ".rs")
}

# ---------------------------------------------------------------------------
# B: an added placement.
# ---------------------------------------------------------------------------
#
# THE HALF THAT ACTUALLY FIRED. `spawn-adapters` refuses a spawn in a module
# nobody placed, and that refusal is answered by one edit — add the module to the
# set — and that edit is what nothing read. It is a two-word line with a paragraph of justification in a
# comment, which reads to a reviewer exactly like the considered decision it may
# or may not be.

violation contains {
	"rule": "spawn add other",
	"verdict": "adapter add refused",
	"subjects": [{"path": placements_module}],
} if {
	some line in added_lines(placements_module)
	regex.match(data.batten.patterns[placement_pattern], line)
}

# ---------------------------------------------------------------------------
# C: could not look.
# ---------------------------------------------------------------------------
#
# A base rev that did not resolve leaves `delta` undefined, so every clause above
# is undefined and the module contributes nothing — which reads as a clean tree
# and is the dead-gate class this repository exists to refuse (CLOUD-251). The
# arm below is what makes the engine record that it could not look.

violation contains {
	"rule": "spawn add other",
	"verdict": "diff read absent",
} if {
	not delta
}

# `missing` is the could-not-look channel for a declared source that would not
# parse, and a module iterating only `lines` reports green over a file it never
# read. `.claude/rules/policy-modules.md`: write the clause.
violation contains {
	"rule": "spawn add other",
	"verdict": "source parse dead",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	engine_source(path)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds the delta they
# read — a `with input as` case fabricates exactly the shape the boundary may be
# unable to produce, which is the class both live instances in this repository
# belonged to. `crates/batten/tests/it/spawn_widening.rs` is the tier that drives
# the compiled binary over a real repository with a real base rev.
#
# THE VOCABULARY IS SUPPLIED, because these are consumer patterns and a case that
# declared none would pass for the wrong reason: `data.batten.patterns[id]` would
# be undefined, the body would not hold, and every deny case would read as clean.

vocabulary := {"patterns": {"spawn-placement-entry": `^\s*"[a-z_]+",\s*$`}}

tree(lines, base) := object.union(vocabulary, {"tree": {
	"lines": lines,
	"missing": {},
	"base-delta": {
		"added": [],
		"edited": object.keys(base),
		"deleted": [],
		"code-changed": [],
		"base-lines": base,
	},
}})

# THE CASE THAT ACTUALLY FIRED, and since CLOUD-2778 the module's one clause.
test_an_added_spawn_placement_is_refused if {
	some v in violation with input as tree(
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`, `	"main_watch",`]},
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`]},
	)
	v.verdict == "adapter add refused"
}

# THE ANTI-VACUITY MIRRORS. Without these every case above is satisfied by a
# module that refuses unconditionally, which is not a gate (CLOUD-418).
test_an_unchanged_engine_module_is_clean if {
	count(violation) == 0 with input as tree(
		{"crates/batten/src/thing.rs": ["#[expect(clippy::disallowed_types)]", "fn a() {}"]},
		{"crates/batten/src/thing.rs": ["#[expect(clippy::disallowed_types)]", "fn a() {}"]},
	)
}

test_an_unchanged_placement_table_is_clean if {
	count(violation) == 0 with input as tree(
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`]},
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`]},
	)
}

# REMOVING A PLACEMENT IS NOT WIDENING, which is the direction the whole rule
# turns on: this branch's remedy is to DELETE the two rows it added, and a
# symmetric predicate would refuse the fix.
test_removing_a_placement_is_clean if {
	count(violation) == 0 with input as tree(
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`]},
		{"policy/spawn-adapters.rego": ["adapters := {", `	"exec",`, `	"main_watch",`]},
	)
}

# AN ADDED ESCAPE IS THE RATCHET'S, NOT THIS MODULE'S (CLOUD-2778). `spawn count
# ahead` counts escapes off the parsed tree; a clause here would be a second,
# text-based authority over the same inventory.
test_an_added_escape_is_not_this_modules_to_refuse if {
	count(violation) == 0 with input as tree(
		{"crates/batten/src/thing.rs": ["fn a() {}", "    clippy::disallowed_types,"]},
		{"crates/batten/src/thing.rs": ["fn a() {}"]},
	)
}

# COULD NOT LOOK IS NOT CLEAN. A base rev that did not resolve leaves every
# clause undefined, which is byte-identical to a clean tree on the decision
# surface — the exact defect this repository refuses.
test_an_unresolvable_base_refuses_rather_than_passing if {
	some v in violation with input as object.union(
		vocabulary,
		{"tree": {"lines": {}, "missing": {}, "base-delta": null}},
	)
	v.verdict == "diff read absent"
}

# And a declared engine source that would not parse is could-not-look too, rather
# than a file with no escapes in it.
test_an_unparsed_engine_source_is_reported if {
	some v in violation with input as object.union(vocabulary, {"tree": {
		"lines": {},
		"missing": {"crates/batten/src/thing.rs": "unparsed"},
		"base-delta": {"added": [], "edited": [], "deleted": [], "code-changed": [], "base-lines": {}},
	}})
	v.verdict == "source parse dead"
}
