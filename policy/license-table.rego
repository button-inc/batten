# METADATA
# description: |
#   Every adopted tool's license row is resolved — the release precondition
#   `CONTRIBUTING.md` states in prose, as a predicate. Ported from
#   `mise-tasks/license-table-check.sh` under CLOUD-843.
#
#   That file's table ends with "Confirm each _to confirm_ entry before that tool
#   is adopted in a shipped release." It is a release precondition and it had no
#   runnable check: three of five rows carried `_to confirm_` in both columns and
#   nothing failed. A rule without its mechanism is half a change (non-negotiable
#   rule 2); this is the other half.
#
#   THE TABLE IS THE DATA AND THIS IS ONLY THE ASSERTION OVER IT. The verdicts
#   are not restated here — a second copy would be a second authority for one
#   fact, and the two would drift.
#
#   DELIBERATELY NARROW. It judges whether a row is RESOLVED, never whether the
#   recorded license is CORRECT: correctness is a human reading an upstream
#   LICENSE file, which no exit code can stand in for. What a gate can prove is
#   that nobody shipped while the question was still open.
#
#   THE COMPATIBILITY COLUMN IS A CLOSED SET, and an unrecognised glyph is a
#   FAILURE rather than a pass — "some other marker" is exactly how an unresolved
#   row would slip past a check that only looked for the literal placeholder.
#
#   ZERO ROWS IS A FAILURE, and it is the reason the predecessor existed at all:
#   a table that parses to no rows passes every per-row assertion vacuously, so a
#   renamed heading or a reformatted table would read as "all rows resolved".
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.license_table

import rego.v1

rules contains "tool grade unclear"

doc := "CONTRIBUTING.md"

# The cells of a table row, or undefined for any line that is not one.
#
# Rows are `| cell | cell | cell | cell |`; the header and the `---` separator
# are skipped BY SHAPE rather than by line number, so inserting a row cannot
# shift the parse.
cells(line) := parts if {
	trimmed := trim_space(line)
	startswith(trimmed, "|")
	endswith(trimmed, "|")
	not contains(trimmed, "---")
	parts := split(trimmed, "|")
}

# One adopted tool's row: its LINE, its name, the license cell and the verdict
# cell.
#
# **THE LINE INDEX IS CARRIED** (review of #928). Without it both row-dependent
# arms emitted the same path-only subject, so several unresolved or invalid rows
# COLLAPSED INTO ONE finding — the gate still exited 2, and the diagnostic could
# not say which row to fix. That is the pointer contract broken by the gate that
# enforces it elsewhere: `path:line`, never a file and a guess.
row contains [index + 1, tool, license, compat] if {
	some index, line in input.tree.lines[doc]
	parts := cells(line)
	count(parts) > 5
	tool := trim_space(parts[1])
	tool != ""

	# The header row names the columns rather than a tool.
	tool != "Tool"
	license := trim_space(parts[3])
	compat := trim_space(parts[4])
}

resolved_verdict := {"✅", "❌"}

violation contains {
	"rule": "tool grade unclear",
	"verdict": "tool grade unclear",
	"subjects": [{"path": doc, "line": line}],
} if {
	some [line, _, license, _] in row
	unresolved_license(license)
}

unresolved_license(license) if license == ""

unresolved_license(license) if contains(license, "to confirm")

violation contains {
	"rule": "tool grade unclear",
	"verdict": "tool grade unclear",
	"subjects": [{"path": doc, "line": line}],
} if {
	some [line, _, license, compat] in row
	not unresolved_license(license)
	not compat in resolved_verdict
}

# THE ANTI-VACUITY ARM. A table that parses to zero rows satisfies every clause
# above, which is the false green the predecessor was written to kill.
violation contains {
	"rule": "tool grade unclear",
	"verdict": "tool grade unclear",
	"subjects": [{"path": doc}],
} if {
	input.tree.lines[doc]
	count(row) == 0
}

# --- the load-time tier ------------------------------------------------------

table(ls) := {"tree": {"lines": {"CONTRIBUTING.md": ls}}}

header := "| Tool | Use | License | Apache-2.0 |"

sep := "| --- | --- | --- | --- |"

test_a_fully_resolved_table_passes if {
	count(violation) == 0 with input as table([header, sep, "| hk | hooks | MIT | ✅ |"])
}

test_an_explicit_incompatible_verdict_is_resolved if {
	count(violation) == 0 with input as table([header, sep, "| thing | x | GPL-3.0 | ❌ |"])
}

test_an_unresolved_license_fails if {
	some v in violation with input as table([header, sep, "| hk | hooks | _to confirm_ | ✅ |"])
	v.verdict == "tool grade unclear"
}

test_a_resolved_license_with_an_unresolved_verdict_still_fails if {
	count(violation) == 1 with input as table([header, sep, "| hk | hooks | MIT | _to confirm_ |"])
}

# **TWO BAD ROWS ARE TWO FINDINGS, EACH NAMING ITS OWN LINE** (review of #928).
# Both row-dependent arms emitted the same path-only subject, so every unresolved
# row in a table collapsed into ONE finding: the gate exited 2 and the diagnostic
# could not say which row to fix.
test_each_unresolved_row_is_named_separately if {
	found := violation with input as table([
		header,
		sep,
		"| hk | hooks | _to confirm_ | ✅ |",
		"| thing | x | _to confirm_ | ✅ |",
	])
	count(found) == 2
	count({subject.line |
		some v in found
		some subject in v.subjects
	}) == 2
}

# AND THE LINE IS THE ROW'S OWN, counted from the top of the file rather than
# from the first row — a reader opens `CONTRIBUTING.md:4` and finds it.
test_the_line_is_where_the_row_actually_is if {
	some v in violation with input as table([
		header,
		sep,
		"| hk | hooks | MIT | ✅ |",
		"| thing | x | _to confirm_ | ✅ |",
	])
	some subject in v.subjects
	subject.line == 4
}

# THE CLOSED SET. "Some other marker" is how an unresolved row slips past a
# check that only looked for the literal placeholder.
test_a_verdict_outside_the_closed_set_fails if {
	count(violation) == 1 with input as table([header, sep, "| hk | hooks | MIT | probably |"])
}

test_a_table_with_no_rows_is_a_failure_not_a_vacuous_pass if {
	count(violation) == 1 with input as table(["# Contributing", "", "no table here"])
}

#MUTANT-SUITE crates/batten/tests/it/license_table.rs
#MUTANT license-vacuous-table-passes|s@count(row) == 0@false@|a_table_with_no_rows_is_a_failure_not_a_vacuous_pass
#MUTANT license-closed-set-unread|s@not compat in resolved_verdict@false@|a_verdict_outside_the_closed_set_fails_over_the_binary
