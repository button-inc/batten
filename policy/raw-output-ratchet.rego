# CLOUD-2488: a verb's output line may not be ADDED as a free-text literal.
#
# WHAT THE DEFECT WAS, MEASURED. The refusal contract (CLOUD-122 / CLOUD-1050) is
# enforced on refusals, through `Refusal`'s private constructor, and on
# advisories, through `emission_census.rs`. Every other line a verb prints is a
# `writeln!` literal no gate reads — 385 `writeln!(out|err` sites in 31 files of
# `crates/batten/src` when this was written — and a literal can carry an
# estimate as easily as a count. On #1191 `land`'s stop exits said nothing about
# what a run spent, and a reader filled the silence with "a full lap of lease
# occupancy" over a run that had spent nothing.
#
# A RATCHET OVER THE DIFF, NOT A STATE RULE, for `cfg-gated-test.rego`'s own
# reason: a gate whose first run refuses hundreds of sites gets an exception
# written for it, and the exception is what rots. The question is the DIRECTION:
# did this branch add one. A new line has a typed home, `output::Progress`,
# whose fields are counts, flags and pointers, so an estimate has nowhere to
# live. Existing sites migrate one verb at a time.
#
# WHAT COUNTS AS A SITE. The engine hands one line at a time, and rustfmt puts
# most calls over three — `writeln!(` / `out,` / `"text …",` — so a one-line
# pattern would miss the majority of the class. A site is either a line whose
# own literal carries text (`raw-writeln-inline`), or a `writeln!(` that opens
# with no literal on its line (`raw-writeln-open`) whose FIRST string line within
# `reach` carries text (`raw-literal-text`). "Carries text" means a letter
# outside every `{…}` placeholder, so `writeln!(out, "{}", x)` is not a site —
# `emission_census.rs`'s `bypasses` owns that shape.
#
# THE RESIDUE IS NAMED RATHER THAN SILENT: `write!` without `ln`, a literal
# assembled by `concat!` or `format!` before the call, a `{{` escape, and a
# format string more than three lines below its `writeln!(`.
#
#MUTANT-SUITE crates/batten/tests/it/raw_output_ratchet.rs
#MUTANT direction-may-invert|s@\tafter > base@\tafter < base@|a_branch_that_adds_a_raw_writeln_is_refused
#MUTANT reach-may-be-empty|s@^reach := \[1, 2, 3\]$@reach := []@|a_multiline_raw_writeln_is_counted
#MUTANT base-may-read-as-empty|s@\tbase := sites(base_lines_of(path))@\tbase := 0@|a_pre_existing_raw_writeln_survives_an_edit
#MUTANT text-test-dropped|s@^\tregex.match(data.batten.patterns\["raw-literal-text"\], line)$@\ttrue@|a_placeholder_only_writeln_is_not_counted
#MUTANT could-not-look-passes|s@^\tnot delta$@\tfalse@|a_missing_delta_is_reported_not_passed
#
# ITS OWN PACKAGE, because `cfg-gated-test.rego` sits in `batten` with the same
# `grew`, `touched` and `violation` partial rules: in one package the two sets
# merge, and each ratchet would report the other's sites under its own verdict.
package batten.raw_output_ratchet

import rego.v1

rules contains "output write loose"

# The branch's own diff, through an object guard: the engine emits `null` where
# the base would not resolve, and `not input.tree["base-delta"]` is dead for it.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# THE COULD-NOT-LOOK ARM, reported rather than passed: a rule that refuses
# nothing over an unreadable base is byte-identical to a branch that added
# nothing.
violation contains {
	"rule": "output write loose",
	"verdict": "diff read absent",
	"subjects": [{"path": "batten.toml"}],
} if {
	not delta
}

inline_site(line) if {
	regex.match(data.batten.patterns["raw-writeln-inline"], line)
}

opens_bare(line) if {
	regex.match(data.batten.patterns["raw-writeln-open"], line)
}

string_line(line) if {
	startswith(trim_space(line), "\"")
}

literal_has_text(line) if {
	regex.match(data.batten.patterns["raw-literal-text"], line)
}

# THE REACH, DECLARED RATHER THAN SCANNED — `cfg-gated-test.rego` measured the
# pairwise scan at 1099s over this tree. rustfmt's form puts the format string
# two lines below `writeln!(`; one spare hop covers a writer expression broken
# over two lines.
reach := [1, 2, 3]

# The format string is the FIRST string line below the open, so a later string
# ARGUMENT (`writeln!(out, "{}", "x")` over three lines) is not mistaken for it.
first_string_hop(lines, index) := hop if {
	some hop in reach
	string_line(lines[index + hop])
	not earlier_string(lines, index, hop)
}

earlier_string(lines, index, hop) if {
	some earlier in reach
	earlier < hop
	string_line(lines[index + earlier])
}

split_site(lines, index) if {
	opens_bare(lines[index])
	hop := first_string_hop(lines, index)
	literal_has_text(lines[index + hop])
}

sites(lines) := count([index |
	some index, line in lines
	inline_site(line)
]) + count([index |
	some index, line in lines
	split_site(lines, index)
])

# An ADDED path has no base side, so its base count is zero, not unreadable.
base_lines_of(path) := lines if {
	lines := delta["base-lines"][path]
}

base_lines_of(path) := [] if {
	not delta["base-lines"][path]
}

touched contains path if {
	some path in delta.added
}

touched contains path if {
	some path in delta.edited
}

grew contains [path, after] if {
	some path in touched
	endswith(path, ".rs")
	after := sites(input.tree.lines[path])
	base := sites(base_lines_of(path))
	after > base
}

violation contains {
	"rule": "output write loose",
	"verdict": "output write loose",
	"subjects": [{"path": path}, {"count": after}],
} if {
	some [path, after] in grew
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE over the three declared `[[pattern]]` rows;
# `crates/batten/tests/it/raw_output_ratchet.rs` is the tier that proves the
# ENGINE builds `base-lines` at all.

edited(path, before, after) := {"tree": {
	"lines": {path: after},
	"base-delta": {"added": [], "edited": [path], "deleted": [], "base-lines": {path: before}},
}}

test_an_added_inline_literal_is_refused if {
	count(violation) == 1 with input as edited("crates/batten/src/a.rs", [], ["writeln!(out, \"land: lap {n}\")?;"])
}

test_an_added_rustfmt_split_literal_is_refused if {
	count(violation) == 1 with input as edited("crates/batten/src/a.rs", [], ["writeln!(", "    out,", "    \"land: lap {n}\",", ")?;"])
}

test_a_placeholder_only_literal_is_not_a_site if {
	count(violation) == 0 with input as edited("crates/batten/src/a.rs", [], ["writeln!(out, \"{}\", x.line())?;", "writeln!(", "    err,", "    \"{} {}\",", ")?;"])
}

test_a_string_argument_after_a_bare_format_is_not_a_site if {
	count(violation) == 0 with input as edited("crates/batten/src/a.rs", [], ["writeln!(", "    out,", "    \"{}\",", "    \"text\",", ")?;"])
}

test_a_pre_existing_site_survives_an_edit if {
	count(violation) == 0 with input as edited(
		"crates/batten/src/a.rs",
		["writeln!(out, \"land: lap\")?;"],
		["writeln!(out, \"land: lap\")?;", "// a new comment"],
	)
}

test_no_delta_is_reported_not_passed if {
	count(violation) == 1 with input as {"tree": {"lines": {}}}
}
