# METADATA
# description: |
#   Prose is not a second authority for a column (CLOUD-234, CLOUD-838; the
#   decision half of the retired `graph-check`, moved into this preset under
#   CLOUD-1221). A body glossing another row's column must agree with the board.
#
#   THE ENGINE EXTRACTS, THIS DECIDES. `batten board check` runs the consumer's
#   declared key and connective expressions over every body — code spans and
#   quoted phrases neutralised, because naming a claim is not making one — and
#   hands over two kinds of span: a `claim`, naming a column some piped row
#   occupies, and an `asserted` span, a capitalised phrase behind a REQUIRED
#   connective, whatever it names. No byte of a body reaches this module.
#
#   A CLAIM THE BOARD CONTRADICTS IS A REFUSAL, keyed to the row whose body
#   makes it. A claim about a row the set does not carry is could-not-look,
#   keyed to the SET, because which closure was piped is the caller's choice and
#   not that row's dishonesty.
#
#   THE ALPHABET'S OWN ANTI-VACUITY ARM (CLOUD-838). The alphabet is the piped
#   set's occupied statuses, never a second copy of the board's list, so a claim
#   naming a column nobody in the set occupies could never match a claim — and a
#   row that LEFT a column was invisible exactly where a stale claim is
#   likeliest. An asserted span outside the alphabet is could-not-look for the
#   set: pipe a row that occupies it. The gloss form of such a claim stays
#   uncovered, because telling one capitalised gloss from another needs the
#   second authority this module must not hold.
#
#   A SET CARRYING NO DESCRIPTIONS cannot be scanned, and says so once; an
#   extraction whose declared expressions would not compose says so too.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/board_check.rs
#MUTANT claim-disagreement-passes|s@^\tactual.status != claim.column$@\tfalse@|a_body_claiming_a_column_the_board_contradicts_is_reported
#MUTANT unscannable-claim-ignored|s@^\tnot span.span in board_alphabet$@\tfalse@|a_claim_naming_a_column_no_piped_issue_occupies_is_refused_not_ignored
#MUTANT outside-claim-ignored|s@^\tnot board_row\[outside.cited\]$@\tfalse@|a_claim_about_an_id_outside_the_piped_set_is_unjudgeable_never_guessed
#MUTANT undescribed-set-scanned|s@^\tcount(board_undescribed) > 0$@\tfalse@|a_set_with_no_descriptions_cannot_be_scanned_for_claims_and_says_so

# `claim <row> <cited> <column>`.
board_claims contains {"row": f[1], "cited": f[2], "column": f[3]} if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 4
	f[0] == "claim"
}

# `asserted <row> <cited> <span>`.
board_asserted contains {"row": f[1], "cited": f[2], "span": f[3]} if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 4
	f[0] == "asserted"
}

board_alphabet contains row.status if {
	some row in board_row
	row.status != ""
}

board_undescribed contains id if {
	some id, row in board_row
	row.described == "no"
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf("unjudgeable-description (%s)", [concat(" ", board_by_num(board_undescribed))])},
	],
} if {
	count(board_undescribed) > 0
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": "status-claim-unscannable (the declared expressions do not compose)"},
	],
} if {
	some line in board_graph_lines
	line == "scan\tbroken"
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [
		{"artifact": claim.row},
		{"artifact": sprintf(
			"status-claim-disagrees (%s claimed %s, board says %s)",
			[claim.cited, claim.column, actual.status],
		)},
	],
} if {
	some claim in board_claims
	actual := board_row[claim.cited]
	actual.status != claim.column
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf(
			"status-claim-unjudgeable (%s claims %s, not in the piped set)",
			[outside.row, outside.cited],
		)},
	],
} if {
	some outside in board_claims
	not board_row[outside.cited]
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf(
			"status-claim-unscannable (%s claims %s is %s, which no piped issue occupies — pipe one that does)",
			[span.row, span.cited, span.span],
		)},
	],
} if {
	some span in board_asserted
	span.span != ""
	not span.span in board_alphabet
}

# --- cases -------------------------------------------------------------------

test_board_a_claim_the_board_contradicts_is_refused_on_the_claiming_row if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Shipped", "other", "no", "0", "set", "-"),
		"claim\tA-1\tA-2\tBuilding",
	])
	board_pointers(found) == {"A-1 status-claim-disagrees (A-2 claimed Building, board says Shipped)"}
}

test_board_a_claim_agreeing_with_the_board_passes if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Shipped", "other", "no", "0", "set", "-"),
		"claim\tA-1\tA-2\tShipped",
	])
	count(found) == 0
}

test_board_a_claim_about_a_row_outside_the_set_is_a_set_keyed_gap if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		"claim\tA-1\tA-99\tShipped",
	])
	board_pointers(found) == {"graph status-claim-unjudgeable (A-1 claims A-99, not in the piped set)"}
}

test_board_an_asserted_column_nobody_occupies_is_a_gap if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "set", "-"),
		"asserted\tA-1\tA-2\tAbandoned",
	])
	board_pointers(found) == {"graph status-claim-unscannable (A-1 claims A-2 is Abandoned, which no piped issue occupies — pipe one that does)"}
}

test_board_an_asserted_column_somebody_occupies_is_left_to_the_claim if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "set", "-"),
		"asserted\tA-1\tA-2\tQueue",
	])
	count(found) == 0
}

test_board_a_set_with_no_bodies_is_one_gap if {
	found := violation with input as board_graph_tree([concat("\t", [
		"row", "1", "A-1", "Queue", "other", "no", "0", "set", "-",
		"declared", "no", "no", "no",
	])])
	board_pointers(found) == {"graph unjudgeable-description (A-1)"}
}

test_board_a_scan_that_would_not_compose_says_so if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		"scan\tbroken",
	])
	board_pointers(found) == {"graph status-claim-unscannable (the declared expressions do not compose)"}
}
