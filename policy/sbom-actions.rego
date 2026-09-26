# Is every row of the pinned-actions licence table whole and pinned? (CLOUD-667,
# ported off `mise-tasks/sbom.sh`'s table reader under CLOUD-1717.)
#
# `[tasks.sbom]` writes each SHA-pinned GitHub Action's license and copyright
# from `mise-tasks/sbom-actions.tsv`. The program refused the table outright on
# two shapes, and those refusals are this module's now; the producer reads only
# rows of the right shape.
#
#   pin parse broken   a row short of three tab-separated fields. A partial row
#                      would write an empty license into a published document —
#                      a field that parses as present and says nothing.
#   pin parse loose    a key that is not `owner/repo@<40-hex>`. The pin is the
#                      whole drift authority (`pin table missing` matches on it):
#                      without it a row maps an action to whatever its default
#                      branch says today rather than to what this commit builds.
#
# Comments and blank lines are skipped by shape. Pointer-only: the table's path
# and the row's line, never a repository name.
#
#MUTANT-SUITE crates/batten/tests/it/sbom_producer.rs
#MUTANT short-row-accepted|s@^\tcount(fields) < 3$@\tfalse@|a_table_row_with_fewer_than_three_fields_is_refused
#MUTANT unpinned-key-accepted|s@^\tnot pinned_key(key)$@\tfalse@|a_key_whose_pin_is_short_of_40_hex_is_refused_too
#MUTANT comments-read-as-rows|s@^\tnot skipped(line)$@\ttrue@|comments_and_blank_lines_in_the_table_are_skipped_by_shape

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.sbom_actions

import rego.v1

rules contains "pin parse other"

table := "mise-tasks/sbom-actions.tsv"

table_lines := input.tree.lines[table]

skipped(line) if startswith(trim_space(line), "#")

skipped(line) if trim_space(line) == ""

pinned_key(key) if regex.match(data.batten.patterns["sbom-action-key"], key)

# `[line number, fields]` for every row the table carries.
rows contains [i + 1, fields] if {
	some i, line in table_lines
	not skipped(line)
	fields := split(line, "\t")
}

violation contains {
	"rule": "pin parse other",
	"verdict": "pin parse broken",
	"subjects": [{"path": table, "line": number}],
} if {
	some [number, fields] in rows
	count(fields) < 3
}

violation contains {
	"rule": "pin parse other",
	"verdict": "pin parse loose",
	"subjects": [{"path": table, "line": number}],
} if {
	some [number, fields] in rows
	count(fields) >= 3
	key := fields[0]
	not pinned_key(key)
}

# --- cases -------------------------------------------------------------------

pin := "3d3c42e5aac5ba805825da76410c181273ba90b1"

# THE KEY IS A LITERAL, NOT THE `table` RULE. Under regorus a rule reference in
# key position inside this helper did not resolve, so `table_lines` was unbound in
# every case: the two refusal cases failed and the two clean ones passed having
# judged no table at all. `test_the_fixture_binds_the_table` below pins that.
tree(rows_given) := {"tree": {"lines": {"mise-tasks/sbom-actions.tsv": rows_given}}}

test_the_fixture_binds_the_table if {
	count(table_lines) == 1 with input as tree([sprintf("actions/checkout@%s\tMIT\tNONE", [pin])])
}

test_a_whole_pinned_row_is_clean if {
	count(violation) == 0 with input as tree([sprintf("actions/checkout@%s\tMIT\tNONE", [pin])])
}

test_a_short_row_is_broken if {
	found := violation with input as tree([sprintf("actions/checkout@%s\tMIT", [pin])])
	{entry.verdict | some entry in found} == {"pin parse broken"}
}

test_a_short_pin_is_loose if {
	found := violation with input as tree(["actions/checkout@deadbeef\tMIT\tNONE"])
	{entry.verdict | some entry in found} == {"pin parse loose"}
}

test_comments_and_blanks_are_skipped if {
	count(violation) == 0 with input as tree(["# a comment", "", "  "])
}
