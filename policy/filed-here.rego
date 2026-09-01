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
# THREE REFUSALS, AND NO ONE OF THEM SUBSUMES ANOTHER. `filed-unrefined` prices
# REFINEMENT; `filed-over-own-diff` prices PROXIMITY; `filed-and-left-open` prices
# a row this branch opened and simply LEFT OPEN. A row can earn the first
# alongside either of the others — "never groomed to Ready" and "names code this
# branch is holding open" are different facts — so they are separate predicates
# over one parse.
#
# THE LAST TWO ARE PARTITIONED RATHER THAN NESTED, and that is a correction rather
# than a taste. `filed-over-own-diff` requires `not cites_only(id)` and
# `filed-and-left-open` requires `cites_only(id)`, so no row can earn both and a
# reviewer never sees two findings for one cause. Drafted without that
# requirement the third arm was strictly WIDER than the second — every row the
# second refused, the third refused too — and the sentence above stopped being
# true of the module it heads.
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
#MUTANT left-open-arm-unpartitioned|s@^\tcites_only(id)$@\ttrue@|a_row_recorded_after_the_base_whose_sec1_names_the_diff_still_refuses
#MUTANT left-open-judges-an-unread-body|s@^\tbody_read$@\ttrue@|an_unread_pr_body_leaves_the_set_unjudged

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

rules contains "filed-and-left-open"

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

# THE BODY WAS READ, so "this PR closes nothing" is a MEASUREMENT rather than an
# absence — the third state the `pr-closes` recorder writes `zero-is-a-count` for.
#
# `closes` alone cannot carry this. An empty `closes` set has three causes that a
# set-membership test flattens into one: the body closes nothing, no PR exists
# yet, and the key reader could not run. The first is a reading and the other two
# are could-not-look, and `filed-and-left-open` refuses over the WHOLE SET rather
# than over a row's properties, so flattening them would refuse every row a branch
# ever filed the first time `verify` runs before the PR is opened — for a remedy
# ("name it in closing form in the PR body") that has nowhere to be written yet.
#
# `-` is the recorder saying it could not read the keys and leaves the set
# unjudged; `0` is a measured nothing and judges it.
body_read if {
	some raw in input.tree.records["pr-closes"]
	columns := split(raw, " ")
	columns[0] == "closes"
	columns[1] != "-"
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

# `filed-and-left-open`: a row this branch filed, that this branch does not close.
#
# THE ARM THE MEASUREMENT ASKED FOR (CLOUD-1311). Three of one session's four
# deferrals were invisible to `filed-over-own-diff` precisely BECAUSE their §1
# named paths outside the diff — `cites_only` exempts those by design, and rightly
# so for a refusal about proximity. Nothing then priced them at all, and the
# detector was a human asking twice.
#
# IT CLASSIFIES NOTHING, which is what keeps non-negotiable rule 3 satisfied. It
# reports a SET: the rows this branch put on the board that it is not landing. The
# author closes one, lets the body close it, or spends an admission whose
# articulation says why it is independent work — and that articulation is
# hash-bound into the commit message, where a reviewer reads it, rather than into
# a turn that ends.
#
# THREE COULD-NOT-LOOKS GUARD IT, and each is a different question.
#   * `body_read` — the forge's answer has not been captured, so the closing
#     remedy is unreachable and the set is unjudged rather than refused.
#   * a non-empty `changed` — a branch holding nothing open has fixed nothing and
#     deferred nothing, so "you filed instead of fixing" is a claim about a diff
#     that does not exist. It is not a dodge: an empty branch cannot land either.
#   * `cites_only`'s own `-` — a record from an older recorder has no §1 column,
#     so the partition cannot be evaluated and the row stays judged as it was
#     before this arm existed.
violation contains {
	"rule": "filed-and-left-open",
	"verdict": "V-FILED-AND-LEFT-OPEN",
	"subjects": [{"artifact": id}],
} if {
	some id, _ in latest
	body_read
	count(changed) > 0
	not id in closes
	not predates_the_branch(id)
	cites_only(id)
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

# CITING IS NOT CLAIMING — for the PROXIMITY refusal, which is the only one it
# was ever about. The row names the path in its body but its declared source of
# truth is somewhere else entirely, so `filed-over-own-diff` is silent.
#
# IT IS NOT SILENT ALTOGETHER, AND THAT IS THE PARTITION. This is the exact shape
# of the three punts nothing caught: a row filed while the branch was open, whose
# §1 points somewhere else, so proximity exempts it and — before this arm — no
# refusal reached it. The case asserts the SET of verdicts rather than a count, so
# a later change collapsing the two arms back together reddens here.
test_a_row_that_only_cites_the_path_is_not_claiming_it if {
	verdicts := {v.verdict | some v in violation} with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
	verdicts == {"V-FILED-AND-LEFT-OPEN"}
}

# NO PR BODY YET IS COULD-NOT-LOOK, not a measured nothing. Without this the arm
# refuses every row a branch filed the first time `verify` runs before the PR is
# opened, naming a remedy that has nowhere to be written.
test_an_unread_body_leaves_the_set_unjudged if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		[],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# AND A FETCH WHOSE KEY READER COULD NOT RUN IS THE SAME ANSWER, which is what
# `zero-is-a-count` exists to keep distinct from `closes 0`.
test_an_unreadable_closing_key_column_leaves_the_set_unjudged if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		["closes -"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

# A BRANCH HOLDING NOTHING OPEN DEFERRED NOTHING. `changed` is empty, so there is
# no diff for the row to have been filed instead of.
test_a_branch_with_no_diff_judges_no_row if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		["closes 0"],
		[],
		"2026-01-01T00:00:00Z",
	)
}

# THE CLOSING REMEDY REACHES THIS ARM TOO, and a body closing a DIFFERENT row does
# not — the anti-vacuity half, without which one closing key buys the whole set.
test_a_left_open_row_the_body_closes_is_exempt if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
		["closes 1:CLOUD-1"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
}

test_closing_one_row_does_not_close_the_set if {
	verdicts := {v.verdict | some v in violation} with input as with_diff(
		[
			"issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs",
			"issue CLOUD-2 2026-02-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs",
		],
		["closes 1:CLOUD-1"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
	verdicts == {"V-FILED-AND-LEFT-OPEN"}
}

# A ROW WRITTEN BEFORE THE BRANCH IS EXEMPT FROM THIS ARM ON THE SAME GROUND it is
# exempt from the proximity one: it cannot be a deferral of a diff that did not
# exist.
test_a_left_open_row_predating_the_branch_is_exempt if {
	count(violation) == 0 with input as with_diff(
		["issue CLOUD-1 2025-12-01T00:00:00Z ready 1,src/a.rs - 1,src/b.rs"],
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

# A NAMED PATH THIS BRANCH IS NOT TOUCHING IS NOT A PUNT AGAINST ITS DIFF — and
# that is still true of the proximity refusal, which stays silent here. It is a
# row left open, so the third arm takes it.
test_a_row_naming_a_path_outside_the_diff_is_not_a_proximity_refusal if {
	verdicts := {v.verdict | some v in violation} with input as with_diff(
		["issue CLOUD-1 2026-02-01T00:00:00Z ready 1,src/z.rs - 1,src/z.rs"],
		["closes 0"],
		["src/a.rs"],
		"2026-01-01T00:00:00Z",
	)
	verdicts == {"V-FILED-AND-LEFT-OPEN"}
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
