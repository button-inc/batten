# A §7 obligation is bound to a case, or it is not landing (CLOUD-472).
#
# THE DEFECT, MEASURED. `ready-lint` gates the SHAPE of a Ready block and
# `verify` gates the CODE, and nothing compared them — so an obligation could be
# written into an issue, pass the refinement gate, and land with no test behind
# it, with every gate in the loop green while it happened. CLOUD-369 is the
# instance: an acceptance bullet describing when a second matrix may be bought
# did not describe the code that buys it, and it merged to `main` by fast-forward,
# CI-confirmed green.
#
# The reconstruction is what makes this structural rather than inattention. The
# acceptance was written first and correctly; a collision forced a mid-implementation
# redesign; the redesign was derived from the problem again rather than from the
# acceptance and silently dropped one condition; and THE TESTS WERE WRITTEN FROM
# THE IMPLEMENTATION, so they assert what the code does. Tests written that way
# can only ever confirm it — they are structurally incapable of catching an
# obligation that was dropped, because a missing behaviour has no code to write a
# test against. The Ready block is the only artifact that still remembers what was
# promised, and nothing read it at implementation time. This does.
#
# WHAT IT CHECKS AND WHAT THE SWEEP CHECKS, because the pair is the obligation
# and neither half alone is. Here: the declared FILE is tracked, and the declared
# SLUG is a `#MUTANT` row in it. `mise run mutant` then applies that row and runs
# its named case, and a SURVIVOR is the finding. So this answers *is there
# something bound to the promise* and the sweep answers *does it discriminate* —
# which is the difference between coverage and a test that cannot fail, the whole
# of CLOUD-418.
#
# IT SCORES NO PROSE (rule 3). It compares a recorded `<file>:<slug>` against
# tracked paths and against lines that begin with a fixed marker. Whether the
# obligation was worth making, and whether the case is a good one, are judgements
# no gate here makes.
#
# THE SET IS THE TRACKER'S, NOT THE AUTHOR'S. `board-issue-groomed`'s
# `obligations` column runs the Ready grammar over the description the tracker
# RETURNED, so an author cannot hand this rule a set it assembled — the same
# forgery control the `verdict` column has, earned when `ready-lint` over a
# self-assembled payload was measured green three times against text in a local
# file, once under an id no row carried.
#
# THE RECORD IS A HISTORY AND THE GATE DECIDES OVER THE PRESENT. Every write to
# a row appends a line, so a row that was readied and then un-readied carries
# both readings. Judging every line makes a corrected Ready block UNFIXABLE: the
# superseded line stands forever, the gate refuses over a promise the tracker no
# longer carries, and the only two remedies are to edit an uncommittable receipt
# or to write a test for work that does not exist. Measured 2026-09-02 on
# CLOUD-1336, filed with a claims object, un-refined minutes later, and still
# refused. So the set is the LATEST line per issue id, compared as fixed-width
# ISO-8601 — the same reading `filed-here.rego` takes, and for the same reason:
# a tracker's own ordering is not a fact any tree surface carries.
#
# AND THE OBLIGATION IS OWED AT LANDING, WHICH IS WHAT THE SET IS NARROWED TO
# (CLOUD-1336). `ready.rs` states the split in its own words — "SHAPE HERE,
# RESOLUTION AT `verify`… at refinement time the case does not exist yet" — and
# the verify it means is the one belonging to the branch that LANDS the row, not
# to whichever branch happened to file it. Judging every recorded row instead put
# two gates in contradiction: `filed-unrefined` prices a filed row a complete
# Ready block, `REQUIRED_CLAIMS` makes `tests` mandatory in it, and this gate then
# demanded that key resolve to a tracked file carrying a `#MUTANT` row — which
# cannot exist for work nobody has built. Measured on CLOUD-1336, filed and
# groomed in one session and unlandable either way: refined, this refused;
# un-refined, `filed-unrefined` did.
#MUTANT-SUITE crates/batten/tests/it/obligations_bound.rs
#MUTANT unbound-file-unread|s@^\tnot obligation_row.file in input.tree.tracked$@\tfalse@|an_obligation_naming_no_tracked_file_is_refused
#MUTANT undeclared-slug-unread|s@^\tnot declares_slug(obligation_row)$@\tfalse@|an_obligation_whose_slug_no_row_declares_is_refused
#MUTANT superseded-line-judged|s@^\trow\.stamp == latest\[row\.id\]$@\ttrue@|a_superseded_obligation_is_not_judged
#MUTANT unlanded-row-judged|s@^\tobligation_row\.id in closes$@\ttrue@|an_obligation_from_a_row_the_pr_does_not_close_is_not_judged

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.obligations_bound

import rego.v1

rules contains "obligation-unbound"

# The board record, or nothing. ABSENT IS NOT EMPTY: a branch whose recorder
# never ran has no key here, Rego reads that as *does not hold*, and this module
# is silent — which is a different claim from a branch that recorded rows
# declaring no obligations.
lines := input.tree.records["board-writes"]

# The rows this branch's pull request says it closes — the ones it is LANDING.
#
# COULD-NOT-LOOK JUDGES NOTHING HERE, and that direction is chosen rather than
# conceded. This module is already silent wherever the board record is absent —
# the store lives under `$GIT_DIR`, is never committed, and dies with the
# container, so a CI runner reaches none of it — and a reading that cannot tell
# whether a row is landing has no promise in front of it to keep. Refusing there
# would refuse every row a branch ever mentioned, with a remedy that belongs to
# whoever eventually builds it. The `filed-unrefined` half of the pair is what
# keeps a filed row from being free, and it fires on the tracker's own verdict
# rather than on anything here.
closes contains key if {
	some raw in input.tree.records["pr-closes"]
	columns := split(raw, " ")
	columns[0] == "closes"
	some key in split(substring(columns[1], indexof(columns[1], ":") + 1, -1), ",")
}

column(columns, at) := value if {
	value := columns[at]
} else := "-"

# Every `<file>:<slug>` this branch's rows declared.
#
# THE `-` IS COULD-NOT-LOOK AND IS SKIPPED, which is the distinction the
# recorder's `stdout-line` read exists to preserve: a prose-dialect block emits
# no line at all, and reading that as "declares no obligations" would exempt
# precisely the rows this gate is for. A row recorded by an older recorder, with
# no column at all, reads the same way and is judged as it was before this
# module existed.
# Every recorded `issue` line, kept whole so the arms below can ask both what it
# says and when it was said.
recorded contains {"id": columns[1], "stamp": columns[2], "columns": columns} if {
	some raw in lines
	columns := split(raw, " ")
	columns[0] == "issue"
}

# The most recent recorded stamp per issue id.
#
# LEXICOGRAPHIC ON A FIXED-WIDTH ISO-8601 INSTANT, which is a comparison and not
# a parse — the recorder writes the tracker's own `updatedAt`, and nothing here
# needs to know what a month is.
latest[id] := stamp if {
	some row in recorded
	id := row.id
	stamps := sort([other.stamp | some other in recorded; other.id == id])
	stamp := stamps[count(stamps) - 1]
}

# THE COUNT IS SEPARATED BY A COLON, NOT A COMMA, AND READING IT WRONG MADE THIS
# GATE UNSATISFIABLE (CLOUD-1402).
#
# `recorder.rs` renders a counted column as `<count><counted-with><joined>`, where
# `joined` is always comma-separated. The obligations column declares
# `counted-with = ":"`, so a row reads `1:path/to/suite.rs:slug`. This rule
# stripped up to the first COMMA — which such a line does not contain — so
# `substring` returned the whole string, `indexof(pair, ":")` found the count's
# own colon, and every obligation resolved to the file `"1"`. That path is in no
# repository's `tracked` set, so the first arm below fired on EVERY row carrying
# an obligation and no author could ever bind one.
#
# It rendered as `1 obligation-unbound`, where the `1` reads as a count and is in
# fact the whole of what the module thought the path was — a wrong answer wearing
# a right answer's shape.
#
# NEITHER TIER CAUGHT IT, and that is the same defect one layer up.
# `.claude/rules/policy-modules.md` records the class: a `with input as` block
# writes the shape it then reads. Every case below spelled the column
# `1,tests/a.rs:slug-one` — a comma the recorder has never written — so the
# load-time tier passed over a parse the engine's own writer contradicts, and the
# compiled tier inherited the same fabricated record. The cases now carry the
# recorder's spelling, and `a_recorded_obligation_uses_the_recorders_own_spelling`
# is the one that would have failed.
#
# The overlap and §1 columns are NOT affected and must not be "fixed" to match:
# they declare no `counted-with`, so `filed-here.rego` reading them with a comma
# is correct. `pr-closes` shares this column's colon and is already read with one.
obligation contains entry if {
	some row in recorded
	row.stamp == latest[row.id]
	packed := column(row.columns, 7)
	packed != "-"
	some pair in split(substring(packed, indexof(packed, ":") + 1, -1), ",")
	at := indexof(pair, ":")
	at > 0
	entry := {
		"id": row.id,
		"file": substring(pair, 0, at),
		"slug": substring(pair, at + 1, -1),
	}
}

# Whether the named file declares the named slug as a `#MUTANT` row.
#
# The marker and the field separator are `mutate`'s own three-field format, and
# matching the PREFIX rather than the whole row is deliberate: the expression and
# the case name are the sweep's business, and a module re-parsing them would be a
# second authority over a format the runner already owns.
declares_slug(entry) if {
	some line in input.tree.lines[entry.file]
	startswith(line, sprintf("#MUTANT %v|", [entry.slug]))
}

# An obligation whose file this repository does not track.
#
# ONE FINDING PER OBLIGATION, so a reviewer sees which promise is unbound rather
# than a count they have to reconstruct. The path leads, because that is what a
# reader opens; the row's id follows it, carried rather than as the pointer.
violation contains {
	"rule": "obligation-unbound",
	"verdict": "test name undefined",
	"subjects": [{"path": obligation_row.file}, {"artifact": obligation_row.id}],
} if {
	some obligation_row in obligation
	obligation_row.id in closes
	not obligation_row.file in input.tree.tracked
}

# An obligation whose file exists and whose slug nothing in it declares.
#
# SEPARATE FROM THE ARM ABOVE because the two are different remedies: a missing
# file means the case was never written, and a missing slug means it was written
# and never given a mutation that could kill it. Collapsing them would hand the
# author one message for two problems.
violation contains {
	"rule": "obligation-unbound",
	"verdict": "test name undefined",
	"subjects": [{"path": obligation_row.file}, {"artifact": obligation_row.id}],
} if {
	some obligation_row in obligation
	obligation_row.id in closes
	obligation_row.file in input.tree.tracked
	not declares_slug(obligation_row)
}

# The predicate's own tests. The SILENT cases carry the weight: every
# could-not-look above is a pass-side property, and a rule that fired on every
# recorded row would satisfy the denies while deciding nothing.

board(record, tracked, lines_by_file) := {"tree": {
	"records": {
		"board-writes": record,
		"pr-closes": ["closes 2:CLOUD-1,CLOUD-2"],
	},
	"tracked": tracked,
	"lines": lines_by_file,
}}

# THE RECORDER'S OWN SPELLING: `<count>:<file>:<slug>`, because the obligations
# column declares `counted-with = ":"`. Written with a comma here for its whole
# life, which is what let the parse above disagree with the writer and stay green.
bound := "issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 1:tests/a.rs:slug-one"

# THE CASE THAT WOULD HAVE CAUGHT IT. Every other case here writes the column and
# then reads it, so all of them stayed green while the parse and the writer
# disagreed. This one asserts the SPELLING against `recorder.rs`'s own rendering
# rule — `<count><counted-with><joined>`, with `counted-with = ":"` declared on
# this column — so a future change to either side reddens here rather than turning
# the gate off in silence.
test_a_recorded_obligation_uses_the_recorders_own_spelling if {
	# The count and its separator, then comma-joined entries. Read wrong, the
	# whole line collapses to the file `"1"` and every obligation is unbindable.
	startswith(bound, "issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 1:")
	some entry in obligation with input as board([bound], [], {})
	entry.file == "tests/a.rs"
	entry.slug == "slug-one"
}

test_a_bound_obligation_is_clean if {
	count(violation) == 0 with input as board(
		[bound],
		["tests/a.rs"],
		{"tests/a.rs": ["#MUTANT slug-one|s@a@b@|the_case"]},
	)
}

test_an_obligation_naming_no_tracked_file_is_refused if {
	some v in violation with input as board([bound], [], {})
	v.verdict == "test name undefined"
}

# THE FILE EXISTS AND THE PROMISE IS STILL UNKEPT. A case with no mutation is a
# case nothing has shown can fail, which is CLOUD-418's whole finding.
test_an_obligation_whose_slug_no_row_declares_is_refused if {
	some v in violation with input as board(
		[bound],
		["tests/a.rs"],
		{"tests/a.rs": ["#MUTANT other-slug|s@a@b@|the_case"]},
	)
	v.verdict == "test name undefined"
}

# COULD NOT LOOK IS NOT A REFUSAL. A prose-dialect block emits no obligations
# line, so the column records `-`, and reading that as "declares none" would
# exempt exactly the rows this gate exists for.
test_a_row_with_no_obligations_column_is_not_judged if {
	count(violation) == 0 with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - -"],
		[],
		{},
	)
}

# A MEASURED ZERO IS AN ANSWER AND PASSES: the object was read and declares no
# obligations, which is a legitimate Ready block.
test_a_row_declaring_no_obligations_passes if {
	count(violation) == 0 with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 0"],
		[],
		{},
	)
}

# A SUPERSEDED LINE IS NOT JUDGED. The record is append-only, so a row readied
# and then un-readied carries both readings; the later one is what the tracker
# now says, and the earlier one is history.
test_a_superseded_obligation_is_not_judged if {
	count(violation) == 0 with input as board(
		[
			bound,
			"issue CLOUD-1 2026-01-02T00:00:00Z unready - - - -",
		],
		[],
		{},
	)
}

# AND THE LATEST LINE IS WHAT DECIDES, not merely the presence of an un-ready
# one — otherwise a row could be un-readied once and never judged again.
test_a_later_ready_line_supersedes_an_earlier_unready_one if {
	some v in violation with input as board(
		[
			"issue CLOUD-1 2026-01-01T00:00:00Z unready - - - -",
			"issue CLOUD-1 2026-01-02T00:00:00Z ready - - - 1:tests/a.rs:slug-one",
		],
		[],
		{},
	)
	v.verdict == "test name undefined"
}

# ONE ROW'S SUPERSESSION SAYS NOTHING ABOUT ANOTHER'S: the latest line is per id.
test_supersession_is_per_issue_id if {
	some v in violation with input as board(
		[
			bound,
			"issue CLOUD-1 2026-01-02T00:00:00Z unready - - - -",
			"issue CLOUD-2 2026-01-03T00:00:00Z ready - - - 1:tests/b.rs:slug-two",
		],
		[],
		{},
	)
	v.subjects[0].path == "tests/b.rs"
}

test_an_absent_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}, "tracked": [], "lines": {}}}
}

# A ROW THIS BRANCH IS NOT LANDING IS A FORWARD REFERENCE. The promise is owed by
# whoever builds the work, at the verify that lands it.
test_an_obligation_from_a_row_the_pr_does_not_close_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"records": {
			"board-writes": [bound],
			"pr-closes": ["closes 1:CLOUD-9"],
		},
		"tracked": [],
		"lines": {},
	}}
}

# AND AN UNREAD `pr-closes` RECORD JUDGES NOTHING, for the same reason rather
# than a weaker one: nothing here can tell whether the row is landing.
test_an_absent_closes_record_judges_nothing if {
	count(violation) == 0 with input as {"tree": {
		"records": {"board-writes": [bound]},
		"tracked": [],
		"lines": {},
	}}
}

test_a_comment_line_declares_no_obligations if {
	count(violation) == 0 with input as board(
		["comment CLOUD-1 2026-01-01T00:00:00Z - - - 1:tests/a.rs:slug-one"],
		[],
		{},
	)
}

# ONE FINDING PER OBLIGATION, and the pointer leads with the path a reader opens.
test_every_unbound_obligation_is_named if {
	paths := {v.subjects[0].path | some v in violation} with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 2:tests/a.rs:one,tests/b.rs:two"],
		[],
		{},
	)
	paths == {"tests/a.rs", "tests/b.rs"}
}
