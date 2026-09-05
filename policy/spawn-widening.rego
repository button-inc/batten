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
# an added spawn escape and an added placement alike.
#
# FAIL CLOSED, WITH NO `bypass_env` AND NO OVERRIDE ROUTE. That is deliberate and
# it follows `shell edit refused`'s precedent, which declares one route with
# neither: the answer to this refusal is not a token to spend, it is that the
# change has the wrong shape. A spawn that genuinely belongs is a decision for a
# groomed row and a human, not an annotation an agent writes about its own work.
#
# WHAT IT DOES NOT CLAIM. It cannot tell a justified spawn from an unjustified
# one — that is a judgement, and non-negotiable rule 3 forbids a gate resolving
# to one. It decides a byte question: did this change add a spawn escape, or add
# a placement admitting one. Both are answerable from the delta, and both were
# unanswered until now.
#
#MUTANT spawn-escape-unread|s@escape_pattern@"nope"@|an_added_spawn_escape_is_refused
#MUTANT placement-widening-unread|s@placement_pattern@"nope"@|an_added_spawn_placement_is_refused
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

rules contains "spawn-widening"

# `input.tree["base-delta"]` is NULL when the base rev did not resolve, and
# `null` is not `undefined` — `not input.tree["base-delta"]` would be FALSE for
# it, which is the slip CLOUD-701's review caught in `spawn-adapters` itself. So
# the delta is bound through a rule that holds only for an object, and every
# predicate below is undefined without it rather than vacuously clean.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# THE PATTERNS ARE `[[pattern]]` ROWS, never inline regexes. One concept, one
# spelling, refused at load rather than duplicated at leisure —
# `.claude/rules/policy-modules.md` is the authority and the reason is measured
# there: one concept was spelled 19 different ways across 17 shell programs
# before the registry existed.
escape_pattern := "clippy-lint-escape"

# THE ONE EXEMPTION, and it is a pattern rather than a clause for the reason the
# registry exists: "the lints a `mod tests` waives" is a concept with one
# spelling, and a second copy of that list here would drift from the row.
#
# A `#[cfg(test)] mod tests` lives inside `crates/batten/src/**`, so the path
# exclusion that keeps `crates/batten/tests/**` out cannot reach it. Measured:
# without this the module refused three files for opening their test module the
# way every file in the crate opens its test module.
idiom_pattern := "clippy-test-idiom"

placement_pattern := "spawn-placement-entry"

# A line that escapes a lint, and is not the test-module idiom.
#
# THE SECOND CONJUNCT IS NARROW BY CONSTRUCTION, because the exempt set is three
# named lints in a `[[pattern]]` row rather than a shape. `too_many_arguments`
# and `cast_precision_loss` are still refused, and both were added by the branch
# that prompted this rule without anybody counting them.
escapes(line) if {
	regex.match(data.batten.patterns[escape_pattern], line)
	not regex.match(data.batten.patterns[idiom_pattern], line)
}

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
	base_lines := delta["base-lines"][path]
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

# ---------------------------------------------------------------------------
# A: an added spawn escape.
# ---------------------------------------------------------------------------

# ENGINE SOURCE ONLY, and `tests/**` is excluded by construction rather than by
# an exemption somebody has to remember. A test module writing
# `#![allow(clippy::expect_used)]` is the idiom every suite in this crate already
# uses — panicking loudly is how a test fails — so a rule firing on those would
# be switched off within a day, which is the failure mode that ends gates.
engine_source(path) if {
	startswith(path, "crates/batten/src/")
	endswith(path, ".rs")
}

violation contains {
	"rule": "spawn-widening",
	"verdict": "spawn write refused",
	"subjects": [{"path": path}],
} if {
	some path in object.keys(input.tree.lines)
	engine_source(path)
	some line in added_lines(path)
	escapes(line)
}

# ---------------------------------------------------------------------------
# B: an added placement.
# ---------------------------------------------------------------------------
#
# THE HALF THAT ACTUALLY FIRED. Clause A refuses a spawn in a module nobody
# placed; `spawn-adapters` then refuses the same thing from the other side. Both
# are answered by one edit — add the module to the set — and that edit is what
# nothing read. It is a two-word line with a paragraph of justification in a
# comment, which reads to a reviewer exactly like the considered decision it may
# or may not be.

violation contains {
	"rule": "spawn-widening",
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
	"rule": "spawn-widening",
	"verdict": "diff read absent",
} if {
	not delta
}

# `missing` is the could-not-look channel for a declared source that would not
# parse, and a module iterating only `lines` reports green over a file it never
# read. `.claude/rules/policy-modules.md`: write the clause.
violation contains {
	"rule": "spawn-widening",
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

vocabulary := {"patterns": {
	"clippy-lint-escape": `^\s*(?:#!?\[\s*(?:expect|allow)\(\s*)?clippy::[a-z_]+`,
	# THE EXEMPTION'S OWN PATTERN, and omitting it made every case here read the
	# engine-source arm as absent. `idiom_pattern` names this id, so a vocabulary
	# without it leaves `data.batten.patterns["clippy-test-idiom"]` undefined —
	# Rego reads undefined as does-not-hold, the exemption never fires, and the
	# deny cases pass for the wrong reason while the allow case that needs it has
	# nothing to assert. Copied byte-for-byte from `batten.toml`'s row, which is
	# what the consumer actually supplies. Found in review.
	"clippy-test-idiom": `^\s*(?:#!?\[\s*(?:expect|allow)\(\s*)?clippy::(?:expect_used|unwrap_used|panic)\b`,
	"spawn-placement-entry": `^\s*"[a-z_]+",\s*$`,
}}

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

# THE CASE THE RULE EXISTS FOR, half one.
test_an_added_spawn_escape_is_refused if {
	some v in violation with input as tree(
		{"crates/batten/src/thing.rs": ["fn a() {}", "    clippy::disallowed_types,"]},
		{"crates/batten/src/thing.rs": ["fn a() {}"]},
	)
	v.verdict == "spawn write refused"
}

# The attribute written on one line reaches the same refusal. Both spellings are
# in this crate, and a pattern anchored on only the continuation form would miss
# every single-line one.
test_a_single_line_escape_is_refused_too if {
	some v in violation with input as tree(
		{"crates/batten/src/thing.rs": ["#[expect(clippy::disallowed_types)]"]},
		{"crates/batten/src/thing.rs": []},
	)
	v.verdict == "spawn write refused"
}

# THE CASE THAT ACTUALLY FIRED, half two.
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

# A TEST MODULE'S OWN ESCAPE IS NOT THIS RULE'S BUSINESS. Every suite in this
# crate opens with one, because panicking loudly is how a test fails — and a rule
# firing on those is a rule that gets switched off.
test_a_test_modules_escape_is_not_refused if {
	count(violation) == 0 with input as tree(
		{"crates/batten/tests/it/thing.rs": ["#![allow(clippy::expect_used)]"]},
		{"crates/batten/tests/it/thing.rs": []},
	)
}

# THE IDIOM EXEMPTION UNDER `src/`, WHICH IS THE ARM THE PATH EXCLUSION CANNOT
# REACH. A `#[cfg(test)] mod tests` lives inside `crates/batten/src/**`, so the
# case above — which is under `tests/` — passes on the path alone and says
# nothing about `idiom_pattern`. Measured before the exemption existed: three
# files were refused for opening their test module the way every file in the
# crate opens its test module.
#
# It is also the case that would have caught the vocabulary gap this file's
# `vocabulary` comment records: with `clippy-test-idiom` undefined the exemption
# never fires, and NOTHING above notices, because every other case here is a deny
# whose refusal an absent exemption only makes more certain.
test_the_test_module_idiom_is_exempt_under_src_too if {
	count(violation) == 0 with input as tree(
		{"crates/batten/src/thing.rs": ["#[allow(clippy::expect_used)]"]},
		{"crates/batten/src/thing.rs": []},
	)
}

# AND THE EXEMPTION IS THREE NAMED LINTS, never a shape. `too_many_arguments` is
# an escape and stays refused — without this the case above reads as "any added
# `clippy::` line under `src/` is fine", which is the rule switched off.
test_a_lint_outside_the_idiom_set_is_still_refused if {
	count(violation) == 1 with input as tree(
		{"crates/batten/src/thing.rs": ["#[allow(clippy::too_many_arguments)]"]},
		{"crates/batten/src/thing.rs": []},
	)
}

# PROSE NAMING A LINT IS NOT AN ESCAPE. This module's own siblings discuss
# `clippy::disallowed_types` at length in doc comments, and a rule reading those
# as escapes would refuse every commit that explains itself.
test_a_doc_comment_naming_a_lint_is_not_an_escape if {
	count(violation) == 0 with input as tree(
		{"crates/batten/src/thing.rs": ["/// `clippy::disallowed_types` refuses this.", "// clippy::expect_used is banned"]},
		{"crates/batten/src/thing.rs": []},
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
