# A turn that cites `path:line` evidence and gives it no OPEN row stranded a
# finding (CLOUD-252, CLOUD-475, CLOUD-775; the decision half of
# `[tasks.finding-sink-check]`, retired under CLOUD-843).
#
# The READING is the engine's: `batten record decide turn-writes` reads the last
# turn of the session's transcript and records how many turns there were,
# whether the last one's prose matched `[[pattern]] finding-citation`, and one
# `call` line per tool call — `call<TAB><name><TAB><key|-><TAB><column|->`, where
# the column is what this clone's `issue-read` receipt recorded for that row.
# This module decides which of those calls is a HOME for the finding.
#
# RECORDED IS NOT SCHEDULED (CLOUD-475, CLOUD-775). A home is:
#   * a row that OPENS — an opening tool called with no row key;
#   * an amendment to a row whose recorded column is OPEN;
#   * a memory or document write, called DIRECTLY.
#
# A mediated call is recorded as `mcp call <server> <method>`, and only its
# filing arms are a home: the retired body credited `batten mcp call` for
# `save_(issue|comment)` alone, so a mediated memory write is not one
# (`[[pattern]] finding-mediated-call`).
# A comment on a Done row, or on a row this clone has no read receipt for, is
# not: could-not-look must not be the cheapest way to buy silence.
#
# Every tracker name and board column is a `[[pattern]]` row — the engine that
# wrote the record knows none of them (non-negotiable rule 1).
#
#MUTANT-SUITE crates/batten/tests/it/finding_sink.rs
#MUTANT class-split-removed|s@^	call\[1\] == "-"$@	true@|a_comment_alone_is_not_a_home
#MUTANT terminal-row-is-a-home|s@^	regex.match(data.batten.patterns\["finding-open-column"\], call\[2\])$@	true@|an_annotation_on_a_terminal_row_still_reports
#MUTANT citation-never-fires|s@^	field("cited") == "true"$@	false@|a_cited_finding_with_no_durable_write_fires
#MUTANT durable-write-unseen|s@^	regex.match(data.batten.patterns\["finding-home-durable"\], call\[0\])$@	false@|a_durable_write_clears_it_under_any_server_alias
#MUTANT mediated-memory-credited|s@^	not regex.match(data.batten.patterns\["finding-mediated-call"\], call\[0\])$@	true@|a_filing_through_the_mediated_route_clears_it

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.finding_sink

import rego.v1

rules contains "turn file other"

lines := input.tree.records["turn-writes"]

field(name) := value if {
	values := {columns[1] |
		some line in lines
		columns := split(line, "\t")
		count(columns) == 2
		columns[0] == name
	}
	count(values) == 1
	some value in values
}

# `[name, key, column]` per recorded call.
calls contains [columns[1], columns[2], columns[3]] if {
	some line in lines
	columns := split(line, "\t")
	count(columns) == 4
	columns[0] == "call"
}

# A row that OPENS: the opening tool, naming no existing row.
home if {
	some call in calls
	regex.match(data.batten.patterns["finding-home-opens"], call[0])
	call[1] == "-"
}

# An amendment to a row whose recorded column is OPEN.
home if {
	some call in calls
	call[1] != "-"
	regex.match(data.batten.patterns["finding-home-amends"], call[0])
	regex.match(data.batten.patterns["finding-open-column"], call[2])
}

# A memory or document write, called directly: a mediated one is not a home.
home if {
	some call in calls
	regex.match(data.batten.patterns["finding-home-durable"], call[0])
	not regex.match(data.batten.patterns["finding-mediated-call"], call[0])
}

violation contains {
	"rule": "turn file other",
	"verdict": "turn file missing",
	"subjects": [{"artifact": sprintf("turn:%s", [field("turns")])}],
} if {
	to_number(field("turns")) > 0
	field("cited") == "true"
	not home
}

# --- cases -------------------------------------------------------------------
#
# `with data.batten.patterns as` supplies the consumer's vocabulary the way the
# committed `[[pattern]]` rows do; the compiled tier runs the real rows.

vocabulary := {
	"finding-home-opens": `save_issue$`,
	"finding-home-amends": `save_(issue|comment)$`,
	"finding-home-durable": `(save_document|write_memory|edit_memory|rename_memory)$`,
	"finding-open-column": `^(backlog|todo|in-progress|in-review)$`,
	"finding-mediated-call": `^mcp call `,
}

turn(cited, calls_lines) := {"tree": {"records": {"turn-writes": array.concat(
	["turns\t1", sprintf("cited\t%s", [cited])],
	calls_lines,
)}}}

test_a_cited_turn_with_no_call_fires if {
	found := violation with input as turn("true", []) with data.batten.patterns as vocabulary
	{entry.verdict | some entry in found} == {"turn file missing"}
}

test_an_uncited_turn_is_clean if {
	count(violation) == 0 with input as turn("false", []) with data.batten.patterns as vocabulary
}

test_a_new_row_is_a_home if {
	count(violation) == 0 with input as turn("true", ["call\tmcp__L__save_issue\t-\t-"])
		with data.batten.patterns as vocabulary
}

test_a_comment_alone_is_not_a_home if {
	found := violation with input as turn("true", ["call\tmcp__L__save_comment\t-\t-"])
		with data.batten.patterns as vocabulary
	count(found) == 1
}

test_an_amendment_to_an_open_row_is_a_home if {
	count(violation) == 0 with input as turn("true", ["call\tsave_comment\tABC-1\ttodo"])
		with data.batten.patterns as vocabulary
}

test_an_amendment_to_a_terminal_row_is_not if {
	found := violation with input as turn("true", ["call\tsave_issue\tABC-1\tdone"])
		with data.batten.patterns as vocabulary
	count(found) == 1
}

test_a_memory_write_is_a_home if {
	count(violation) == 0 with input as turn("true", ["call\tmcp__serena__write_memory\t-\t-"])
		with data.batten.patterns as vocabulary
}

test_a_mediated_memory_write_is_not_a_home if {
	found := violation with input as turn("true", ["call\tmcp call serena write_memory\t-\t-"])
		with data.batten.patterns as vocabulary
	count(found) == 1
}

test_a_mediated_filing_is_a_home if {
	count(violation) == 0 with input as turn("true", ["call\tmcp call Linear save_issue\t-\t-"])
		with data.batten.patterns as vocabulary
}

test_no_turns_judges_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {"turn-writes": ["turns\t0", "cited\ttrue"]}}}
		with data.batten.patterns as vocabulary
}
