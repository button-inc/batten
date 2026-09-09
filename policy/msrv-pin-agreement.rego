# METADATA
# description: |
#   The declared floor and the dependency bot's constraint are the toolchain
#   pin's derived copies, so all three must name the same compiler — CLOUD-593 and
#   CLOUD-658, ported from `mise-tasks/msrv-pin-agreement.sh` under CLOUD-843.
#
#   The gate this replaced answered "do the floor and the pin disagree?" by
#   compiling the whole workspace a second time at a second toolchain — ~32-50s
#   per PR, in the required checks, plus a toolchain fetch. That was the right
#   shape while the two numbers were deliberately INDEPENDENT: a floor below the
#   pin is a claim about a compiler nothing here runs, and the only way to verify
#   such a claim is to run it.
#
#   CLOUD-593 removed the independence. This project ships compiled binaries and
#   its source is public so the community can maintain them; nobody consumes the
#   crate as a library and nobody obtains it by compiling, so the floor promises
#   nothing to nobody. What the field still does is feed MSRV-aware dependency
#   resolution, keeping the graph inside what we actually build with — and the
#   honest value for that is the compiler we actually build with. Once the policy
#   is "these are equal", the predicate is a text equality and the second compile
#   buys nothing the equality does not.
#
#   The floor was twelve releases behind the pin, which froze two crates and
#   rejected a third outright. The compiling gate was green throughout, because
#   the two numbers agreed. It was never the gate that would notice.
#
#   MAJOR.MINOR, AND ONLY THAT. A floor of `1.97` against a pin of `1.97.1` is the
#   same compiler line and must compare equal; the field is a MINIMUM and a patch
#   component there says nothing extra. Comparing the strings raw would demand the
#   patch be written into the floor — legal, but claiming a precision the field
#   does not carry, and reddening on every patch bump of the pin, which is exactly
#   the noise that gets a gate switched off.
#
#   A THIRD PATH SINCE CLOUD-658, and it is what makes handing the cargo ecosystem
#   to the bot safe rather than a regression. One updater reads the floor from the
#   manifest natively; the one this repository uses does not, so MSRV-aware
#   resolution survives the handover only if the number is written into the bot's
#   config by hand. CLOUD-593's argument applies unchanged: a copy is not the
#   defect, an UNGATED copy is — so the third copy is one more path here rather
#   than a new hazard.
#
#   THE CONSTRAINT IS READ FROM INSIDE ITS BLOCK, never by scanning the file for a
#   `rust` key: that file discusses the pin at length in its comments, and a gate a
#   COMMENT could answer is a gate satisfied by deleting the value it explains.
#   Comments are stripped for the same reason, and only where a `//` opens a line
#   or follows whitespace, so a URL's own `//` survives.
#
#   THE PREDICATE IS THIS CONSUMER'S. Which files carry the copies, and that the
#   pin is the authority rather than the floor, are facts about this consumer —
#   non-negotiable rule 1.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the values and the files they
#   came from, never a line of any of the three.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.msrv_pin_agreement

import rego.v1

rules contains "msrv-pin-agreement"

manifest_path := "Cargo.toml"

pins_path := "mise.toml"

renovate_path := "renovate.json5"

# The first quoted value on a line, which is how all three numbers are written.
quoted(text) := value if {
	spans := regex.find_n(data.batten.patterns["md-quoted-span"], text, 1)
	value := replace(spans[0], "\"", "")
}

# The compiler LINE, which is the whole comparison: a patch component says
# nothing the minimum does not.
line_of(version) := concat(".", [parts[0], parts[1]]) if {
	parts := split(version, ".")
	count(parts) >= 2
}

line_of(version) := version if {
	count(split(version, ".")) < 2
}

# --- the three numbers -------------------------------------------------------
#
# The floor is anchored on the key at LINE START, so a `rust-version` inside a
# dependency table cannot answer for the workspace's own declaration.
floor := value if {
	some line in input.tree.lines[manifest_path]
	top_level(line)
	contains(line, "=")
	key(line) == "rust-version"
	value := quoted(line)
}

# The bare key, left of the first `=`. Compared WHOLE rather than by prefix: a
# `rustup` entry beside the pin would otherwise answer for it, and two answers
# for one key is a conflict the evaluator reports as an error rather than a
# verdict.
key(line) := replace(trim_space(substring(line, 0, indexof(line, "="))), "\"", "")

# AT LINE START, which is what separates a table's own declaration from a key
# nested inside another one. A `rust-version` under a dependency table is that
# dependency's claim and must not answer for the workspace's.
top_level(line) if {
	not startswith(line, " ")
	not startswith(line, "\t")
}

# The inline-table form is the one this repository uses; the bare form is
# accepted too, since the manifest format permits it and a gate that understood
# only one spelling would fail OPEN on the other.
pin := value if {
	some line in input.tree.lines[pins_path]
	top_level(line)
	contains(line, "=")
	key(line) == "rust"
	contains(line, "version")
	after := substring(line, indexof(line, "version"), -1)
	value := quoted(after)
}

pin := value if {
	some line in input.tree.lines[pins_path]
	top_level(line)
	contains(line, "=")
	key(line) == "rust"
	not contains(line, "version")
	value := quoted(line)
}

renovate_lines := lines if {
	lines := input.tree.lines[renovate_path]
}

# A `//` opening a line, or following whitespace. The URL in a schema key keeps
# its own.
decommented(line) := "" if {
	startswith(trim_space(line), "//")
}

decommented(line) := substring(line, 0, indexof(line, " //")) if {
	not startswith(trim_space(line), "//")
	contains(line, " //")
}

decommented(line) := line if {
	not startswith(trim_space(line), "//")
	not contains(line, " //")
}

constraints_start := i if {
	some i, line in renovate_lines
	contains(decommented(line), "constraints")
	contains(decommented(line), ":")
}

constraints_end := e if {
	closers := {j |
		some j, line in renovate_lines
		j >= constraints_start
		contains(decommented(line), "}")
	}
	e := min(closers)
}

constraint := value if {
	some j, line in renovate_lines
	j >= constraints_start
	j <= constraints_end
	text := decommented(line)
	contains(text, "rust")
	contains(text, ":")
	after := substring(text, indexof(text, "rust"), -1)
	value := quoted(after)
}

# --- the could-not-look arms -------------------------------------------------
#
# Each is its own refusal, because silence on any one of the three would read as
# agreement — which is the failure the whole family exists to prevent.
violation contains {
	"rule": "msrv-pin-agreement",
	"verdict": "pin declare missing",
	"subjects": [{"path": manifest_path}],
} if {
	input.tree.lines[manifest_path]
	not floor
}

violation contains {
	"rule": "msrv-pin-agreement",
	"verdict": "pin declare missing",
	"subjects": [{"path": pins_path}],
} if {
	input.tree.lines[pins_path]
	not pin
}

# An ABSENT constraint is MSRV-aware resolution silently switched off, not a
# neutral omission: the updater this repository uses does not read the floor from
# the manifest at all.
violation contains {
	"rule": "msrv-pin-agreement",
	"verdict": "pin declare missing",
	"subjects": [{"path": renovate_path}],
} if {
	renovate_lines
	not constraint
}

# --- the divergences ---------------------------------------------------------
#
# Each derived copy is compared against the pin in its OWN rule rather than in one
# condition joined by an or. A joined condition is one no mutation could name, and
# a path no mutation can name is a path nothing proves is load-bearing — the
# retiring program recorded the mutant runner refusing exactly that shape.
violation contains {
	"rule": "msrv-pin-agreement",
	"verdict": "pin declare other",
	"subjects": [{"artifact": sprintf("%s rust-version %s", [manifest_path, floor])}],
} if {
	line_of(floor) != line_of(pin)
}

violation contains {
	"rule": "msrv-pin-agreement",
	"verdict": "pin declare other",
	"subjects": [{"artifact": sprintf("%s constraints.rust %s", [renovate_path, constraint])}],
} if {
	line_of(constraint) != line_of(pin)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves three
# separate `line_sources` paths into one map in a single evaluation — a `with
# input as` block fabricates exactly that map (CLOUD-845), and the agreement IS
# the join across the three. `crates/batten/tests/it/msrv_pin_agreement.rs` is
# that tier.

tree(files) := {"tree": {"lines": files}}

cargo(version) := ["[workspace.package]", sprintf("rust-version = \"%s\"", [version])]

tools(version) := ["[tools]", sprintf("rust = { version = \"%s\", profile = \"minimal\" }", [version])]

bot(version) := [
	"{",
	"  \"$schema\": \"https://docs.renovatebot.com/renovate-schema.json\",",
	"  // the pin is the authority; this is its derived copy",
	"  constraints: {",
	sprintf("    rust: \"%s\",", [version]),
	"  },",
	"}",
]

three(floor_v, pin_v, bot_v) := tree({
	"Cargo.toml": cargo(floor_v),
	"mise.toml": tools(pin_v),
	"renovate.json5": bot(bot_v),
})

test_all_three_naming_one_compiler_line_is_clean if {
	count(violation) == 0 with input as three("1.97", "1.97.1", "1.97")
}

# A patch component in the pin and none in the floor is the SAME compiler line.
test_a_patch_component_is_not_a_divergence if {
	count(violation) == 0 with input as three("1.97", "1.97.4", "1.97")
}

test_a_floor_behind_the_pin_is_refused if {
	some v in violation with input as three("1.85", "1.97.1", "1.97")
	v.verdict == "pin declare other"
}

# The whole defect the retired gate was blind to: both numbers were `1.x`
# throughout the twelve releases they were apart, so a major-only comparison
# passes it.
test_a_major_only_comparison_would_not_catch_this if {
	some v in violation with input as three("1.85", "1.97.1", "1.97")
	v.subjects[0].artifact == "Cargo.toml rust-version 1.85"
}

test_a_bot_constraint_naming_another_compiler_is_refused if {
	some v in violation with input as three("1.97", "1.97.1", "1.85")
	v.verdict == "pin declare other"
}

test_an_absent_constraint_is_refused if {
	some v in violation with input as tree({
		"Cargo.toml": cargo("1.97"),
		"mise.toml": tools("1.97.1"),
		"renovate.json5": ["{", "}"],
	})
	v.verdict == "pin declare missing"
}

# The bot's config discusses the pin at length in its comments, and a gate a
# COMMENT could answer is a gate satisfied by deleting the value it explains.
test_a_commented_constraint_does_not_answer_for_the_real_one if {
	some v in violation with input as tree({
		"Cargo.toml": cargo("1.97"),
		"mise.toml": tools("1.97.1"),
		"renovate.json5": ["{", "  // constraints: { rust: \"1.97\" } was here", "}"],
	})
	v.verdict == "pin declare missing"
}

test_the_bare_pin_spelling_is_understood_too if {
	count(violation) == 0 with input as tree({
		"Cargo.toml": cargo("1.97"),
		"mise.toml": ["[tools]", "rust = \"1.97.1\""],
		"renovate.json5": bot("1.97"),
	})
}

# A neighbouring key whose name STARTS with the pin's must not answer for it —
# two answers for one key is an evaluation error rather than a verdict.
# A key nested inside ANOTHER table is that table's claim, never the workspace's.
test_a_nested_floor_cannot_answer_for_the_workspace if {
	some v in violation with input as tree({
		"Cargo.toml": ["[workspace.dependencies.demo]", "  rust-version = \"1.97\""],
		"mise.toml": tools("1.97.1"),
		"renovate.json5": bot("1.97"),
	})
	v.verdict == "pin declare missing"
}

# Equality, not a bound: a floor AHEAD of the pin is a divergence too.
test_a_floor_ahead_of_the_pin_is_refused_too if {
	some v in violation with input as three("1.99", "1.97.1", "1.97")
	v.verdict == "pin declare other"
}

test_a_constraint_ahead_of_the_pin_is_refused_too if {
	some v in violation with input as three("1.97", "1.97.1", "1.99")
	v.verdict == "pin declare other"
}

# A `rust` key OUTSIDE the constraints block cannot answer for it.
test_a_rust_key_outside_the_block_does_not_answer_for_it if {
	some v in violation with input as tree({
		"Cargo.toml": cargo("1.97"),
		"mise.toml": tools("1.97.1"),
		"renovate.json5": ["{", "  packageRules: [{ rust: \"1.97\" }],", "}"],
	})
	v.verdict == "pin declare missing"
}

test_a_neighbouring_key_does_not_answer_for_the_pin if {
	count(violation) == 0 with input as tree({
		"Cargo.toml": cargo("1.97"),
		"mise.toml": ["[tools]", "rustup = \"1.28\"", "rust = \"1.97.1\""],
		"renovate.json5": bot("1.97"),
	})
}

test_an_absent_floor_is_refused if {
	some v in violation with input as tree({
		"Cargo.toml": ["[workspace.package]", "edition = \"2024\""],
		"mise.toml": tools("1.97.1"),
		"renovate.json5": bot("1.97"),
	})
	v.verdict == "pin declare missing"
}

#MUTANT-SUITE crates/batten/tests/it/msrv_pin_agreement.rs
#MUTANT floor-not-compared|s@^\tline_of(floor) != line_of(pin)$@\tfalse@|a_floor_behind_the_pin_is_refused_and_both_are_named
#MUTANT constraint-read-but-not-compared|s@^\tline_of(constraint) != line_of(pin)$@\tfalse@|a_bot_constraint_naming_another_compiler_is_refused
#MUTANT compares-major-only|s@:= concat(".", \[parts\[0\], parts\[1\]\])@:= parts[0]@|a_floor_behind_the_pin_is_refused_and_both_are_named
