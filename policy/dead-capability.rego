# CLOUD-1423: a declared verb that nothing reaches, gated at the moment it is
# ADDED.
#
# WHAT THE DEFECT WAS, MEASURED 2026-09-04. PR #812 and PR #829 shipped roughly
# 4,000 lines of landing engine — `lease.rs` at 3,050 lines, `gitwrite.rs`'s
# three-way rebase, `land.rs`'s five lap steps — with ten `lease` arms and four
# `land` verbs fully declared, 16 committed man pages, completions regenerated in
# three shells, and NO CALL SITE. Every gate in the set read clean over it:
# `module-layering` asks whether a module has a row, `spawn-adapters` which
# modules spawn, `tests/it/surface.rs` that the man pages match the binary,
# `module-map-check` that every module has a mem:core row. All membership
# questions; none is reachability. The tell was visible only by grepping for
# callers, which no gate did.
#
# A RATCHET OVER THE DIFF, NOT A STATE RULE, AND THAT IS THE WHOLE DESIGN.
# Measured before writing a line: 61 of this tree's 154 declared verbs have no
# in-tree caller, and they are overwhelmingly not the defect — `config show`,
# `doctor session`, `init`, `baseline`, `policy rule`, the seven `state` arms and
# six `task` arms are OPERATOR verbs. A CLI's whole point is that a human invokes
# it, so it has no in-tree caller by construction. A state rule refuses all 61 on
# its first run, which is the shape `bash-surface-not-growing`'s preamble refuses
# in as many words and which `cfg-gated-test` records for its own ~40: a gate
# whose first firing is a false positive gets an exception written for it, and
# the exception is what rots.
#
# THE TEST ARM IS ABSENT, AND ITS ABSENCE IS A DECISION (grooming 2026-09-18).
# The row asked for "a verb exercised only by its own tests IS the dead-capability
# shape". That inverts the testing trophy — an integration test over the compiled
# binary is the tier this repository invests in hardest, and a gate treating that
# coverage as evidence of deadness pushes an author to wire a fake production
# caller rather than write a test, which is the row's own stated failure mode
# through the other door. It is also not expressible: test helpers factor the
# verb prefix out, so the tokens never appear adjacent in source —
# `tests/it/record_closes.rs:47` builds argv as `.arg("record").arg("closes")`,
# and `tests/it/task_registry.rs:629` passes only the tail `["tick", …]` to a
# helper that prepends it. Any text arm under-counts coverage and refuses live,
# well-tested verbs. A ratchet needs no test arm at all, so it cannot punish one.
#
# WHY THE VERB SET COMES FROM `path:` LITERALS. The committed
# `completions/batten.bash` case-arm tree is the other candidate and was
# cross-checked against this one: both yield the same 154 verbs, with ZERO in one
# and not the other. The literal is the simpler predicate; the completion needs
# clap's recursive `help` subtrees filtered out. What the literal costs is a
# dependency on rustfmt's indentation, so `a_surface_that_declares_no_verb_is_a_
# read_failure` exists: extracting zero verbs must redden rather than read clean.
#
# NO INLINE REGEX. The `[[pattern]]` rule refuses one at load, and a pattern row
# could not help anyway — the needle is a different verb on every iteration, and
# a `[[pattern]]` row is a static string. Every test here is a string builtin,
# the spelling `cfg-gated-test.rego` uses for the same reason.
#
#MUTANT-SUITE crates/batten/tests/it/dead_capability.rs
#MUTANT declaration-arm-dropped|s@^\tnot declared_unreached(verb)$@\ttrue@|a_branch_that_adds_a_verb_with_a_declaration_is_clean
#MUTANT ratchet-may-read-untouched|s@^\tSURFACE in touched$@\ttrue@|a_pre_existing_unreached_verb_survives_an_unrelated_edit
#MUTANT base-may-read-as-empty|s@\tnot base_verbs\[verb\]$@\ttrue@|a_pre_existing_unreached_verb_survives_an_edit_to_the_surface
#MUTANT reach-may-read-as-absent|s@^\tnot reached(verb)$@\ttrue@|a_branch_that_adds_a_wired_verb_is_clean
# METADATA
# description: |
#   The schema binding, which `every-package-binds-input` refuses a package for
#   omitting (CLOUD-876). Its reason is measured rather than stylistic: an
#   unannotated module reading `input.tree.trackd` passes `opa check -s` at exit
#   0, so an unbound package is exactly the module the type check cannot see.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.dead_capability

import rego.v1

rules contains "verb reach missing"

# The file the `CommandDecl` table lives in. One spelling, read three times.
SURFACE := "crates/batten/src/surface.rs"

# The surfaces a production caller may live in: whatever the row's `line_sources`
# filled, minus the surface file itself and the crate.
#
# WHICH PATHS THOSE ARE IS THE CONSUMER'S, and it stays in `batten.toml` under
# non-negotiable rule 1 — a list of this repository's own directories inside a
# module would be the identifier the core must not carry. The module knows only
# "a caller lives outside the crate".
#
# The row's `line_sources` must name `.claude/**`, and the issue's four-surface
# list would have been wrong without it: the harness hook registrations there are
# the only caller of `adjudicate`, the one verb this whole engine exists to
# serve. A list that refuses `adjudicate` is a list nobody believes twice.
call_surfaces contains path if {
	some path, _ in input.tree.lines
	path != SURFACE
	not startswith(path, "crates/")
}

# The branch's own diff, BOUND THROUGH AN OBJECT GUARD because `null` is not
# `undefined`: the engine emits `null` where the base would not resolve, and
# `not input.tree["base-delta"]` is dead for exactly that value.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# THE COULD-NOT-LOOK ARM. A shallow clone, a detached CI checkout with the base
# unfetched, or a fork with no `origin/main` has no delta — and a ratchet that
# refuses nothing is byte-identical to a branch that added nothing on the
# decision surface, so the read failure is REPORTED rather than passed.
violation contains {
	"rule": "verb reach missing",
	"verdict": "diff read absent",
	"subjects": [{"path": "batten.toml"}],
} if {
	not delta
}

touched contains path if {
	some path in delta.added
}

touched contains path if {
	some path in delta.edited
}

# An ADDED file has no base side, and its base verb set is therefore empty rather
# than unreadable: a new surface file declaring a verb nothing reaches is the
# same defect arriving in one commit instead of two.
base_lines := lines if {
	lines := delta["base-lines"][SURFACE]
}

base_lines := [] if {
	not delta["base-lines"][SURFACE]
}

# The verb path a `CommandDecl` line declares, or undefined.
#
# `path: ""` is the ROOT (`surface.rs`'s `ROOT` decl, the binary itself) and is
# not a verb; dropping it here keeps the caller arm from being asked an
# unanswerable question about the empty string.
decl_path(line) := verb if {
	trimmed := trim_space(line)
	startswith(trimmed, "path: \"")
	rest := trim_prefix(trimmed, "path: \"")
	verb := split(rest, "\"")[0]
	verb != ""
}

verbs_in(lines) := {verb |
	some line in lines
	verb := decl_path(line)
}

declared_verbs := verbs_in(input.tree.lines[SURFACE])

base_verbs := verbs_in(base_lines)

# A file's code, comments dropped and lines joined.
#
# THE JOIN IS WHAT MAKES THIS CORRECT, not a convenience. Measured: `lease guard`
# is invoked at `.github/workflows/test.yml:181-183` as
# `"…/batten" --config-in "…" \` / `lease guard \` — the program on one line and
# the verb on the next. A line-local predicate reports that live verb dead, which
# is a false refusal on the one arm the row says IS wired.
#
# COMMENTS ARE DROPPED FIRST because the row's own measurement is that every
# textual hit over `land`/`lease` was "prose or a comment". Counting those as
# callers is the dead-gate direction: the gate would read clean over the exact
# defect it was written for.
code_text(path) := concat(" ", [line |
	some line in input.tree.lines[path]
	not startswith(trim_space(line), "#")
])

# Something in a production surface invokes this verb.
#
# THE NEEDLE IS THE VERB SURROUNDED BY SPACES, not `batten <verb>` adjacently,
# and the repository's own spelling is why: flags sit between the program and the
# verb (`batten --config-in "…" lease guard`), so an adjacency test fails on the
# live invocation above. Requiring the file to name `batten` at all is what keeps
# a bare ` check ` in an unrelated script from reading as a call site.
#
# The residue is named rather than silent: a verb whose every call site spells it
# across a pipe into another program, or under an alias, reads as unreached. That
# lands in the OVER-deny direction for a ratchet whose remedy is one declaration
# line, which is the cheap direction to be wrong in.
reached(verb) if {
	some path in call_surfaces
	text := code_text(path)
	contains(text, "batten")
	contains(text, concat("", [" ", verb, " "]))
}

# The author declared that nothing reaches it, and why.
#
# THE TOKEN IS DELIBERATELY NOT A NEW SPELLING of a concept this repository
# already has: `bash-surface-not-growing`'s `admits_with = "# stays-bash:"` is
# the same move for a different surface, and `shell-retirement.rego`'s
# `declares_it_stays_bash` reads it exactly this way. One spelling per concept.
# THE VERB IS QUOTED, AND THE FIRST SPELLING WAS A DEFECT found while writing the
# declarations this arm governs. Matching the verb as a bare substring means the
# PROSE declares verbs too: an ordinary reason — "lease acquire is driven by land
# lap in process" — also contains `land lap`, which IS wired, so the stale arm
# fired on a verb nobody declared. Quoting binds a declaration to exactly one
# verb and cannot be tripped by a sentence naming another.
#
# It also makes the line independently readable, which is what matters for
# something written once and read years later: `# unreached: "lease acquire"
# CLOUD-1338 …` says what it declares without the reader holding the
# `CommandDecl` table in their head.
#
# THE MARKER IS RUST'S, AND THE FIRST SPELLING WAS UNREACHABLE. It matched
# `# unreached:`, borrowed from `bash-surface-not-growing`'s `# stays-bash:` —
# but that precedent lives in shell and bats files, where `#` IS the comment.
# `surface.rs` is the only file this arm ever reads and it is Rust, so no line in
# it can ever start with `#`: the declaration route was declared and unwalkable,
# the same CLOUD-122 defect this bundle's first row fixed one surface over. What
# carries across from the precedent is the TOKEN, `unreached:`, not the marker.
declared_unreached(verb) if {
	some line in input.tree.lines[SURFACE]
	trimmed := trim_space(line)
	startswith(trimmed, "//")
	contains(trimmed, "unreached:")
	contains(trimmed, concat("", ["\"", verb, "\""]))
}

# The ratchet: a verb this branch ADDED, that nothing reaches, undeclared.
unreached contains verb if {
	SURFACE in touched
	some verb in declared_verbs
	not base_verbs[verb]
	not reached(verb)
	not declared_unreached(verb)
}

violation contains {
	"rule": "verb reach missing",
	"verdict": "verb reach missing",
	"subjects": [{"path": SURFACE}, {"artifact": verb}],
} if {
	some verb in unreached
}

# THE OTHER DIRECTION, and it is the one that rots quietly. A declaration that has
# outlived its reason reads as coverage: the verb is wired, the line still says
# nothing reaches it, and the next reader believes the line.
stale contains verb if {
	SURFACE in touched
	some verb in declared_verbs
	declared_unreached(verb)
	reached(verb)
}

violation contains {
	"rule": "verb reach missing",
	"verdict": "verb reach stale",
	"subjects": [{"path": SURFACE}, {"artifact": verb}],
} if {
	some verb in stale
}

# THE ANTI-VACUITY ARM, and it guards a real dependency rather than a
# hypothetical one. The verb set is read from `path: "…"` literals at rustfmt's
# indentation; a formatting change that moves them yields an EMPTY set, every
# downstream clause goes undefined, and the module reports clean over a surface
# it could not read. That is byte-identical to a tree with no verbs, which is the
# dead-gate class this row exists to close.
violation contains {
	"rule": "verb reach missing",
	"verdict": "diff read absent",
	"subjects": [{"path": SURFACE}],
} if {
	input.tree.lines[SURFACE]
	count(declared_verbs) == 0
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/dead_capability.rs` is the
# tier that proves the ENGINE builds `base-lines` and `lines` for these paths at
# all — a `with input as` case fabricates the very shape the engine may be unable
# to produce, which is how a dead clause survives. Both tiers, and the second is
# not optional.

surface_with(verb) := [
	"    CommandDecl {",
	concat("", ["        path: \"", verb, "\","]),
	"        id: \"x\",",
	"    },",
]

tree_with(lines, base, callers) := {"tree": {
	"lines": object.union({"crates/batten/src/surface.rs": lines}, callers),
	"base-delta": {
		"added": [],
		"edited": ["crates/batten/src/surface.rs"],
		"base-lines": {"crates/batten/src/surface.rs": base},
	},
}}

test_a_branch_that_adds_an_unreached_verb_is_refused if {
	some v in violation with input as tree_with(surface_with("lease acquire"), [], {})
	v.verdict == "verb reach missing"
}

test_a_branch_that_adds_a_wired_verb_is_clean if {
	count(violation) == 0 with input as tree_with(
		surface_with("lease acquire"),
		[],
		{"mise.toml": ["run = 'batten lease acquire --ttl 60'"]},
	)
}

# THE RATCHET PROPERTY. Without it this is the 61-verb state check that grooming
# rejected: an untouched surface must refuse nothing at all.
test_a_pre_existing_unreached_verb_survives_an_unrelated_edit if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/src/surface.rs": surface_with("lease acquire")},
		"base-delta": {
			"added": [],
			"edited": ["README.md"],
			"base-lines": {},
		},
	}}
}

test_a_pre_existing_unreached_verb_survives_an_edit_to_the_surface if {
	count(violation) == 0 with input as tree_with(
		surface_with("lease acquire"),
		surface_with("lease acquire"),
		{},
	)
}

test_a_branch_that_adds_a_verb_with_a_declaration_is_clean if {
	count(violation) == 0 with input as tree_with(
		array.concat(
			["    // unreached: \"lease acquire\" CLOUD-1338 driven by land lap in process"],
			surface_with("lease acquire"),
		),
		[],
		{},
	)
}

test_a_declaration_on_a_wired_verb_is_refused if {
	some v in violation with input as tree_with(
		array.concat(
			["    // unreached: \"lease acquire\" CLOUD-1338 driven by land lap in process"],
			surface_with("lease acquire"),
		),
		[],
		{"mise.toml": ["run = 'batten lease acquire --ttl 60'"]},
	)
	v.verdict == "verb reach stale"
}

# A COMMENT IS NOT A CALL SITE, which is the row's own measurement: every textual
# hit over `land` and `lease` was prose or a comment.
test_a_commented_invocation_does_not_reach if {
	some v in violation with input as tree_with(
		surface_with("lease acquire"),
		[],
		{"mise.toml": ["# batten lease acquire is what land lap calls"]},
	)
	v.verdict == "verb reach missing"
}

# THE CONTINUATION CASE. The program and the verb on separate lines is the live
# spelling at `.github/workflows/test.yml:181-183`.
test_a_verb_on_a_continuation_line_is_reached if {
	count(violation) == 0 with input as tree_with(
		surface_with("lease guard"),
		[],
		{".github/workflows/test.yml": ["  \"$BIN/batten\" --config-in \"$CFG\" \\", "    lease guard \\", "    \"$SHA\""]},
	)
}

test_could_not_look_is_reported_rather_than_passed if {
	some v in violation with input as {"tree": {
		"lines": {"crates/batten/src/surface.rs": surface_with("lease acquire")},
		"base-delta": null,
	}}
	v.verdict == "diff read absent"
}

test_a_surface_that_declares_no_verb_is_a_read_failure if {
	some v in violation with input as tree_with(["fn main() {}"], [], {})
	v.verdict == "diff read absent"
}
