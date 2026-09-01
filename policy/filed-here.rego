# CLOUD-514's two refusals, as a module rather than a shell gate (ported under
# CLOUD-1051).
#
# THE ARITHMETIC IT REVERSES. Every other gate here prices FAILING to record
# something — a turn that cites evidence and writes nothing, a PR that defers
# without naming an issue. Filing satisfies all of them in seconds while
# finishing costs a diff, a suite and a landing, so spinning a defect in the
# branch's own diff onto the board is cheaper than fixing it and the board
# becomes the escape hatch every guardrail points at. Making the new row cost a
# complete Ready block is what flips that, without anything judging whether a
# given spin-off was lazy.
#
# TWO REFUSALS, AND NEITHER SUBSUMES THE OTHER. `filed-unrefined` prices
# REFINEMENT; `filed-over-own-diff` prices PROXIMITY. A row can earn both —
# "never groomed to Ready" and "names code this branch is holding open" are
# different facts — so they are separate predicates over one parse.
#
# The second exists because the first turned out to be payable in typing. A Ready
# block is prose, and prose is the one currency an agent has without limit:
# measured 2026-08-20, four rows filed in three and a half minutes, twelve more
# spent writing four blocks, and the recorder stored `ready` for every one. The
# toll did not reverse the arithmetic — it certified the punts.
#
# WHAT IT STILL DOES NOT DO, because non-negotiable rule 3 forbids it: it scores
# no prose, compares no semantics, and decides nothing about whether a spin-off
# was lazy. It reads columns the recorder wrote and compares them to literals and
# to path lists the engine resolved.
#
# THE VERDICT IS THE TRACKER'S, NOT THE AUTHOR'S, and that property lives in the
# recorder rather than here: `[[recorder]]`'s verdict column lints the tracker's
# RESPONSE to the create. `ready-lint` over a payload the caller assembles is
# forgeable and was measured to be — green three times over text in a local file
# during this issue's own refinement, once under an id no row carried.
#
# THREE STATES PER COLUMN, NOT TWO. `-` is the recorder saying it could not look
# and PASSES; `0` is a measurement that found nothing and passes; a value is a
# reading to judge. Mapping "not answered" onto "refused" would turn a verdict
# about the environment into a verdict about the row, which is the confusion the
# recorder's own three-valued write exists to avoid.
#
# FAILS OPEN on everything it cannot establish. No record, no delta, no branch —
# each leaves the module silent, and a branch that predates the recorder can
# never have a record at all: the store lives under `$GIT_DIR`, is never
# committed, and dies with the container.
#
# POINTER, NEVER PAYLOAD (rule 4): a refusal names the id, and for the diff
# refusal one tracked path. The recorder never wrote a title or a body, so there
# is none here to leak, and only a path this repository tracks can reach the
# overlap column at all.
#MUTANT-SUITE crates/batten/tests/it/filed_here.rs
#MUTANT unrefined-row-unread|s@^\tlatest\[id\].verdict == "unready"$@\tfalse@|an_unready_create_stops_the_lap
#MUTANT closing-row-still-priced|s@^\tnot id in closes$@\ttrue@|a_row_the_pr_closes_is_exempt

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.filed_here

import rego.v1

rules contains "filed-unrefined"

rules contains "filed-over-own-diff"

# The record, or nothing. ABSENT IS NOT EMPTY: a branch whose recorder never ran
# has no key here at all, Rego reads that as *does not hold*, and every rule below
# is silent. An empty list would be a measured nothing and would say the branch
# filed no rows, which is a different claim.
lines := input.tree.records["board-writes"]

# One column of a record line, or could-not-look.
#
# THE TAIL COLUMNS ARE OPTIONAL BY CONSTRUCTION. A record written by an older
# recorder is shorter, so a column past its end reads `-` and passes — a branch is
# never refused for a question its recorder could not ask.
column(columns, at) := value if {
	value := columns[at]
} else := "-"

# Every `issue` line, keyed by its position so a later reading can supersede an
# earlier one.
#
# A LINE THIS READER CANNOT PARSE IS SKIPPED AND NEVER JUDGED. A `comment` line is
# recorded and deliberately never gated: a comment on the row that already owns a
# finding is the honest common case, and pricing it would push the pressure toward
# silence, which is the failure the sink rules exist to catch.
entry[at] := row if {
	some at, raw in lines
	columns := split(raw, " ")
	columns[0] == "issue"
	columns[1] != ""
	row := {
		"id": columns[1],
		"updated": column(columns, 2),
		"verdict": column(columns, 3),
		"overlap": column(columns, 4),
		"sec1": column(columns, 6),
	}
}

# THE LAST VERDICT PER ID WINS, NOT EVERY LINE. The recorder writes a fresh line
# when a row this branch filed is groomed, and reading every line would leave the
# creation-time `unready` standing beside the `ready` that supersedes it — the
# state that held one PR for its whole life with the remedy it printed
# unreachable. A later line is a later reading of the same row by the same
# mechanism, so it is simply the current one.
latest[id] := row if {
	some at, row in entry
	id := row.id
	at == max({other | some other, candidate in entry; candidate.id == id})
}

# The branch's own diff, as the engine resolved it. `base-delta` is `null` when
# the base rev does not resolve, so `changed` does not hold at all and both
# refusals below go silent — could-not-look, never a fabricated empty diff that
# would pass every row on ignorance.
delta := input.tree["base-delta"]

changed contains path if {
	some path in delta.added
}

changed contains path if {
	some path in delta.edited
}

changed contains path if {
	some path in delta.deleted
}

# THE ROWS THIS PR CLOSES ARE EXEMPT, and without this the gate inverts. The
# overlap is recomputed against the LANDING diff, so it fires on a row the branch
# filed AND THEN FIXED — its paths are in the diff by construction. Every honest
# file-then-fix would then need the override, and a routinely-overridden gate is
# bypassed rather than satisfied; worse, the cheapest way to dodge it becomes not
# filing the row at all, which is the property the board exists for in a container
# that can be reclaimed at any moment.
#
# The record is `<count>:<key>,<key>` from the boundary's own capture of what the
# forge returned. Absent — no PR yet, or a fetch that could not run — means no
# exemption, exactly as the shell behaved with stdin closed.
closes contains key if {
	some raw in input.tree.records["pr-closes"]
	columns := split(raw, " ")
	columns[0] == "closes"
	some key in split(substring(columns[1], indexof(columns[1], ":") + 1, -1), ",")
}

# `filed-unrefined`: a row this branch created was never groomed to Ready.
#
# `ready` passes and so does `-`; only the tracker's own `unready` refuses.
violation contains {
	"rule": "filed-unrefined",
	"verdict": "issue file unclear",
	"subjects": [{"artifact": id}],
} if {
	some id
	latest[id].verdict == "unready"
}

# The overlap column is `<count>,<path>...`, and only a count with at least one
# path after it is a reading to judge. `-` is could-not-look and `0` is a
# measurement that found nothing; both pass, and both pass for reasons no
# one-line mutation can falsify — the count arm, the emptiness of the path list
# and the intersection each independently protect it.
named_paths(packed) := paths if {
	at := indexof(packed, ",")
	at > 0
	regex.match(data.batten.patterns["positive-count"], substring(packed, 0, at))
	paths := split(substring(packed, at + 1, -1), ",")
}

# THE PATHS A ROW NAMES THAT THIS BRANCH IS CHANGING.
#
# A RULE KEYED BY ID, NOT A FUNCTION, and that is a scheduling fact rather than a
# style one: a function call needs its arguments bound, so `some id` followed by
# `overlapping(id)` cannot be ordered and the module fails to compile. Keying the
# rule makes the id the thing being iterated instead of a value to supply.
overlapping[id] := hits if {
	some id, row in latest
	hits := {path |
		some path in named_paths(row.overlap)
		path in changed
	}
}

# SKIP 1 — WRITTEN BEFORE THIS BRANCH EXISTED. A punt is a deferral of work in the
# diff you are holding open; a row recorded before the branch's base cannot be
# one, by construction. Measured: 3 of 3 refusals on one PR were rows already In
# Review, landed before that branch was cut, and the override had to be spent on
# all three.
#
# Both sides are fixed-width ISO-8601 UTC, so `<` is chronological order. Either
# side missing skips the arm rather than deciding on it: could-not-look
# manufactures neither a pass nor a refusal.
predates_the_branch(id) if {
	base := delta["base-date"]
	is_string(base)
	updated := latest[id].updated
	updated != "-"
	updated < base
}

# SKIP 2 — THE ROW'S OWN §1 NAMES NOTHING IN THE DIFF. Independent of the
# timestamp and worse, because no ordering fixes it: citing a path as evidence is
# indistinguishable, to a path-name intersection, from claiming work on it. A row
# whose declared source of truth names none of the diff is not claiming this work,
# whatever its prose cites.
#
# `-` is could-not-look and leaves the row judged as before, so a record from an
# older recorder is never silently exempted.
cites_only(id) if {
	packed := latest[id].sec1
	packed != "-"
	count({path |
		some path in named_paths(packed)
		path in changed
	}) == 0
}

# `filed-over-own-diff`: a row this branch filed names code this branch has open.
#
# ONE FINDING PER PATH, as the shell emitted, so a reviewer sees which file rather
# than a count they have to go and reconstruct.
violation contains {
	"rule": "filed-over-own-diff",
	"verdict": "issue file same",
	"subjects": [{"path": path}, {"artifact": id}],
} if {
	some id, hits in overlapping
	some path in hits
	not id in closes
	not predates_the_branch(id)
	not cites_only(id)
}

# The predicate's own tests. The SILENT cases are the load-bearing half: every
# skip above is a pass-side property, and a rule that fired on every row would
# satisfy the denies while deciding nothing.

board(record) := {"tree": {"records": {"board-writes": record}}}

with_diff(record, closes_record, changed_paths, base) := {"tree": {
	"records": {"board-writes": record, "pr-closes": closes_record},
	"base-delta": {"added": changed_paths, "edited": [], "deleted": [], "code-changed": [], "base-date": base},
}}

test_an_unready_row_is_refused if {
	some v in violation with input as board(["issue CLOUD-1 2026-01-01T00:00:00Z unready - - -"])
	v.verdict == "issue file unclear"
}

test_a_ready_row_is_silent if {
	count(violation) == 0 with input as board(["issue CLOUD-1 2026-01-01T00:00:00Z ready - - -"])
}

# COULD NOT LINT IS NOT A REFUSAL. `ready-lint` exiting 2, or failing to run at
# all, records `-` — a verdict about the environment, not about the row.
test_an_unanswered_verdict_passes if {
	count(violation) == 0 with input as board(["issue CLOUD-1 2026-01-01T00:00:00Z - - - -"])
}

# A GROOM SUPERSEDES THE CREATE, which is what keeps the third remedy reachable.
test_the_last_reading_of_a_row_is_the_current_one if {
	count(violation) == 0 with input as board([
		"issue CLOUD-1 2026-01-01T00:00:00Z unready - - -",
		"issue CLOUD-1 2026-01-02T00:00:00Z ready - - -",
	])
}

test_a_comment_is_recorded_and_never_gated if {
	count(violation) == 0 with input as board(["comment CLOUD-1 2026-01-01T00:00:00Z - - - -"])
}

test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as board(["", "nonsense"])
}

# NO RECORD IS NO ANSWER. A branch that predates the recorder has no file, and
# refusing over that would be a verdict about the store.
test_an_absent_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_row_naming_this_branch_s_own_diff_is_refused if {
	some v in violation with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/a.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
	v.verdict == "issue file same"

	# THE ORDER IS THE STATEMENT: the tracked path leads, because that is what a
	# reader should open, and `first_pointer` takes the first path-bearing subject
	# as the finding's own pointer. The row's id follows it — carried, never the
	# pointer — so both reach a reader and neither is prose.
	v.subjects == [{"path": "src/a.rs"}, {"artifact": "CLOUD-1"}]
}

test_a_row_this_pr_closes_is_the_work_landing if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/a.rs"],
		["closes 1:CLOUD-1"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

test_a_row_written_before_the_branch_cannot_be_its_punt if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2025-12-01T00:00:00Z ready 1,src/a.rs - 1,src/a.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# CITING IS NOT CLAIMING. The row names the path in its body but its declared
# source of truth is somewhere else entirely.
test_a_row_that_only_cites_the_path_is_not_claiming_it if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# ZERO IS A MEASUREMENT AND `-` IS COULD-NOT-LOOK, and both pass.
test_a_measured_zero_overlap_passes if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 0 - -"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

test_an_unanswered_overlap_passes if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready - - -"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# A NAMED PATH THIS BRANCH IS NOT TOUCHING IS NOT A PUNT AGAINST ITS DIFF.
test_a_row_naming_a_path_outside_the_diff_passes if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/z.rs - 1,src/z.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# COULD NOT READ THE BASE DATE LEAVES EVERY ROW JUDGED AS BEFORE, rather than
# exempting the ones it cannot order.
test_an_unresolvable_base_date_still_judges_the_row if {
	some v in violation with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/a.rs"],
		["closes 0"],
		["src/a.rs"],
		null,
	)
	v.verdict == "issue file same"
}

# BOTH REFUSALS AT ONCE, because neither subsumes the other.
test_a_row_can_earn_both_refusals if {
	verdicts := {v.verdict | some v in violation} with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z unready 1,src/a.rs - 1,src/a.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
	verdicts == {"issue file unclear", "issue file same"}
}
