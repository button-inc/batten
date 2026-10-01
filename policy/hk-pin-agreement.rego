# hk's version is pinned identically in `mise.toml` and in `hk.pkl`'s `amends`
# URL, retired off the `hk-version` task body under CLOUD-1991.
#
# `mise.toml` pins the hk BINARY; `hk.pkl` amends the hk CONFIG PACKAGE by URL.
# The two move independently, and a bump to one without the other is the moment
# the hook config silently runs against a schema its binary did not ship — so
# both must name one version, and the refusal is also the reminder to revisit
# `hk.pkl` for what the new version offers. The predecessor was two `grep -oE`
# pipelines and a string comparison in shell.
#
# ─── WHY A MODULE AND NOT A PRESET ───────────────────────────────────────────
#
# It names one task runner's pin table and one hook runner's config file. Pulled
# out into consumer facts, what remains is "two files agree about a string",
# which decides nothing — `mise-pin-agreement.rego`'s reason, one tool over.
#
# ─── WHAT IS STRICTER THAN THE SHELL, SAID RATHER THAN SLIPPED IN ───────────
#
# The predecessor compared the FIRST `hk@<version>` in `hk.pkl` (`head -n1`).
# This compares every one, so a second amends line naming another version is
# refused rather than shadowed. Both of the predecessor's `:?` arms survive: an
# `hk.pkl` that names no version while `mise.toml` pins one is refused, and so is
# the mirror. A `mise.toml` this could not read decides nothing, since the
# document binding below is undefined then.
#
#MUTANT hk-pin-disagreement-passes|s@^\tamended.version != pin$@\tfalse@|a_version_the_amends_url_names_differently_is_refused
#MUTANT hk-amends-unnamed-passes|s@^\tcount(amends) == 0$@\tfalse@|an_hk_pkl_naming_no_version_is_refused
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
package batten.hk_pin_agreement

import rego.v1

rules contains "tool pin other"

config := "hk.pkl"

# The pin table, bound only when the manifest parsed to an object, so every arm
# below is UNDEFINED rather than vacuously clean when it was not read.
tools := t if {
	t := input.tree.documents["mise.toml"].tools
	is_object(t)
}

pin := v if {
	v := tools.hk
	is_string(v)
}

lines := ls if {
	ls := input.tree.lines[config]
	is_array(ls)
}

# Every version an `amends` URL in `hk.pkl` names, with its line.
amends contains {"line": i + 1, "version": match[1]} if {
	some i, line in lines
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-amends-version"], line, -1)
}

# A: the config package names a different hk than the binary pin.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": config, "line": amended.line}, {"path": "mise.toml"}],
} if {
	some amended in amends
	amended.version != pin
}

# B: the binary is pinned and `hk.pkl` names no version at all.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": config}, {"path": "mise.toml"}],
} if {
	pin
	lines
	count(amends) == 0
}

# C: `hk.pkl` names a version and the pin table carries no `hk` string.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": "mise.toml"}, {"path": config, "line": amended.line}],
} if {
	# `object.get`, never `tools.hk`: the dotted read is hoisted into a binding
	# that fails on an absent key before the `not` ever sees it, which made this
	# arm undecidable — measured, by this file's own case below.
	#
	# `tools` FIRST, positively: the claim is about a pin table that WAS read.
	# regorus lets the `not` below succeed over an undefined `tools`, so an unread
	# manifest read as "no `hk` pin" and fired this arm over nothing.
	tools
	not is_string(object.get(tools, "hk", null))
	some amended in amends
}

# --- the load-time tier ------------------------------------------------------
#
# The predicate over a fabricated input; `crates/batten/tests/it/tracked_absent.rs`
# shows the engine fills `documents` and `lines` for the committed row.

pattern := {"hk-amends-version": `hk@([0-9]+\.[0-9]+\.[0-9]+)`}

amends_line(version) := sprintf("amends \"package://github.com/jdx/hk/releases/download/v%s/hk@%s#/Config.pkl\"", [version, version])

tree(pinned, pkl) := {"tree": {
	"documents": {"mise.toml": {"tools": pinned}},
	"lines": {"hk.pkl": pkl},
}}

test_agreeing_versions_are_clean if {
	count(violation) == 0 with input as tree({"hk": "1.56.1"}, ["// header", amends_line("1.56.1")])
		with data.batten.patterns as pattern
}

test_a_version_the_amends_url_names_differently_is_refused if {
	found := violation with input as tree({"hk": "1.57.0"}, ["// header", amends_line("1.56.1")])
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 2}
}

test_an_hk_pkl_naming_no_version_is_refused if {
	found := violation with input as tree({"hk": "1.56.1"}, ["amends \"package://example/Config.pkl\""])
		with data.batten.patterns as pattern
	count(found) == 1
}

test_a_pin_table_without_hk_is_refused if {
	found := violation with input as tree({"rust": "1.90"}, [amends_line("1.56.1")])
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "mise.toml"}
}

test_a_second_amends_line_is_read_rather_than_shadowed if {
	found := violation with input as tree({"hk": "1.56.1"}, [amends_line("1.56.1"), amends_line("1.40.0")])
		with data.batten.patterns as pattern
	count(found) == 1
}

test_an_unread_manifest_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}, "lines": {"hk.pkl": [amends_line("1.56.1")]}}}
		with data.batten.patterns as pattern
}
