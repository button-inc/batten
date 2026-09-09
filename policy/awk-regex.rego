# METADATA
# description: |
#   No shell program hands awk a regex through `-v`, where escape handling is
#   implementation-defined — ported from `mise-tasks/awk-regex-check.sh` under
#   CLOUD-843.
#
#   A pattern passed through `awk -v` goes through the assignment's escape
#   processing before awk ever sees it as a regex, and what that does to a
#   backslash is not defined across implementations. gawk strips `\(` to `(`
#   with a warning; mawk keeps it. So the same pattern is a literal paren on one
#   machine and a capturing group on the other.
#
#   Not theoretical: `ready-lint` matched its §8 label that way. It worked on
#   mawk locally and matched NOTHING on the gawk runner, so the clause that
#   exists to catch a blocker claimed without a relation went back to passing
#   silently. A gate that cannot match its own label does not fail; it passes.
#
#   THE PREDICATE IS THE USE, NOT THE VALUE. A literal with no backslash is safe
#   today and unsafe the moment someone adds one, and a variable's runtime
#   content is invisible to any static check. So this flags a `-v` name that the
#   awk program then uses in REGEX POSITION — `~ name` or `match(…, name)` —
#   whatever the value looks like at the call site. `-v` for a plain value stays
#   fine, which is most of its use.
#
#   IDENTIFIERS ARE COMPARED WHOLE, WHICH IS STRICTLY BETTER THAN THE SHELL HAD.
#   The predecessor built a per-name regex and guarded the boundary with a
#   trailing character class. A module may not do that at all — an inline regex
#   is refused at load, and a name-parameterised one is not a concept with one
#   spelling — so the port reads the identifier that FOLLOWS `~` or the comma
#   and compares it whole. `name` and `namespace` are then distinct by
#   construction rather than by a character class that has to be got right.
#
#   Output is a pointer (non-negotiable rule 4): `path:line` and the name, never
#   the command.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.awk_regex

import rego.v1

rules contains "awk-regex"

# Only lines that reach awk at all. The shell narrowed the same way with a grep
# for `awk` before it looked for `-v`, and the narrowing is what keeps this from
# reading every `-v` in the tree as an awk assignment.
awk_lines contains [path, index, line] if {
	some path, file_lines in input.tree.lines
	some index, line in file_lines
	contains(line, "awk")
	contains(line, "-v")
}

# Every name assigned with `-v` on that line.
assigned contains [path, index, line, name] if {
	some [path, index, line] in awk_lines
	some capture in regex.find_all_string_submatch_n(
		data.batten.patterns["awk-v-assignment"],
		line,
		-1,
	)
	name := capture[1]
}

# The identifier a fragment starts with, or undefined where it starts with
# anything else.
leading(fragment) := found[0] if {
	found := regex.find_n(
		data.batten.patterns["leading-identifier"],
		trim_space(fragment),
		1,
	)
	count(found) == 1
}

# `x ~ name` — the identifier immediately after a `~`.
in_regex_position(line, name) if {
	some part in array.slice(split(line, "~"), 1, count(split(line, "~")))
	leading(part) == name
}

# `match(s, name)` — the identifier after a comma inside a `match(` call.
in_regex_position(line, name) if {
	some call in array.slice(split(line, "match("), 1, count(split(line, "match(")))
	some arg in array.slice(split(call, ","), 1, count(split(call, ",")))
	leading(arg) == name
}

violation contains {
	"rule": "awk-regex",
	"verdict": "pattern carry unsafe",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some [path, index, line, name] in assigned
	in_regex_position(line, name)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE hands this module the
# shell corpus, which is what a fabricated `input.tree.lines` asserts into
# existence. `crates/batten/tests/it/awk_regex.rs` is that tier.

scan(line) := {"tree": {"lines": {"mise-tasks/demo.sh": [line]}}}

test_a_name_used_with_tilde_is_refused if {
	some v in violation with input as scan("awk -v re=\"$p\" '$0 ~ re'")
	v.verdict == "pattern carry unsafe"
}

test_match_is_regex_position_too if {
	count(violation) == 1 with input as scan("awk -v re=\"$p\" '{ if (match($0, re)) print }'")
}

test_a_value_compared_with_equals_is_fine if {
	count(violation) == 0 with input as scan("awk -v want=\"$p\" '$1 == want'")
}

test_a_value_printed_is_fine if {
	count(violation) == 0 with input as scan("awk -v n=\"$p\" '{ print n, $0 }'")
}

test_an_inline_regex_is_the_recommended_form if {
	count(violation) == 0 with input as scan("awk '$0 ~ /^ISSUE-[0-9]+$/'")
}

# THE PREFIX CASE, and the one the whole-identifier comparison exists for.
test_a_name_that_prefixes_another_is_not_confused_for_it if {
	count(violation) == 0 with input as scan("awk -v re=\"$p\" '$0 ~ rex'")
}

# TWO NAMES ON ONE LINE COLLAPSE TO ONE FINDING, and that is the pointer
# contract rather than lost coverage. A `subjects` member is a tagged pointer —
# `{path, line}` here — so two hazards on the same line produce the same subject
# and `violation` is a set. The predecessor printed a line per NAME; a reader
# following this pointer opens the line and sees both. What must not collapse is
# a hazard on a DIFFERENT line, which the case below pins.
test_two_names_on_one_line_are_one_pointer if {
	count(violation) == 1 with input as scan("awk -v a=\"$x\" -v b=\"$y\" '$0 ~ a || $1 ~ b'")
}

test_a_hazard_on_each_of_two_lines_is_two_findings if {
	count(violation) == 2 with input as {"tree": {"lines": {"mise-tasks/demo.sh": [
		"awk -v a=\"$x\" '$0 ~ a'",
		"awk -v b=\"$y\" '$1 ~ b'",
	]}}}
}

test_a_line_that_never_reaches_awk_is_not_judged if {
	count(violation) == 0 with input as scan("grep -v re && echo '$0 ~ re'")
}

#MUTANT-SUITE crates/batten/tests/it/awk_regex.rs
#MUTANT awk-regex-position-unread|s@in_regex_position(line, name)$@true@|a_value_compared_with_equals_is_fine_over_the_binary
#MUTANT awk-regex-prefix-unread|s@leading(part) == name@startswith(part, name)@|a_name_that_prefixes_another_is_not_confused_for_it
