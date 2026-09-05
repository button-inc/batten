# Every measured invocation path is inside its latency budget, and README
# publishes the budget this gate enforces (CLOUD-207, retired off
# `mise-tasks/perf-assert.sh` under CLOUD-1321).
#
# THE MEASUREMENT CANNOT HAPPEN INSIDE THE ENGINE, which is why this reads a
# record rather than taking a reading. `check` is declared `read` and structurally
# cannot spawn, so hyperfine stays a command on PATH and something outside has to
# invoke it — the same split `validator-verdict-clean` already has for pkl, and
# the reason `[[rule.tools]]` exists at all. The producer runs in
# `.github/workflows/perf.yml`, where the measurement's release build and quiet
# machine live; this decides.
#
# THE KEY IS THE SAFETY PROPERTY. `input.tree["tool-verdict"]` is keyed by
# (tool, pinned version, input digest), so a record taken over a binary that has
# since been rebuilt lives under a different name and DOES NOT ANSWER — it is
# absent rather than stale. That is what makes reading a measurement taken
# elsewhere honest, and it is a property the predecessor's stdin pipe could not
# have: a file of records carries no statement about what produced it.
#
# THE BUDGET IS AN ABSOLUTE CEILING, NOT A RATCHET, and that is deliberate. 100ms
# is the Command Line Interface Guidelines' floor for a response that reads as
# instant, and it is the number CLOUD-207 names. A tight band around the measured
# value — "p95 must stay within 20% of yesterday's" — is the obvious alternative
# and is wrong twice over: a shared runner's p95 varies by more than that between
# two runs of identical bytes, so the gate would fire on noise. The ceiling being
# ~20-30x the measured value IS the tolerance band. "Did this commit make it
# slower than the trunk" is a different question with a different answer shape,
# and it is CLOUD-172's — `perf-gate`'s — not this one's.
#
# WHY THERE IS A `check` ROW NOW, when the predecessor deliberately had none.
# `perf-assert.sh` argued that `check` is bounded by the repository it is pointed
# at, so no ceiling could tell a large consumer tree apart from a regression, and
# `rules/rust.md` records the absence as a stated decision. The `perf`
# arm this row gates is not that: it is a ONE-RULE FIXTURE repo, so it measures
# process start plus config load plus trust resolution plus one rule, all of which
# are bounded by what batten costs rather than by a consumer's tree. That is
# budgetable on exactly the reasoning that budgets `noop`. It is NOT the
# deletion-linear term CLOUD-1321 flattened — that is a property of one module
# over a 152k-line corpus, measured in seconds, and its gate is
# `crates/batten/tests/it/shell_retirement_cost.rs`, which discriminates growth
# SHAPE rather than machine speed. Two gates, two subjects, and neither is claimed
# to be the other.
#
# THE README CLAUSE. Publishing a budget in one file and enforcing it in another
# is two authorities for one number, and the one that drifts is always the
# published one — it has no mechanism. So this reads README's budget column and
# refuses when it disagrees with `budgets` below. It judges the BUDGET, never the
# measured figures: those are a snapshot of one machine at one commit and are
# expected to be stale between `perf` runs, so gating them would fail the repo for
# the passage of time.
#MUTANT-SUITE crates/batten/tests/it/perf_assert.rs
# A `[` IS A BRACKET EXPRESSION UNTIL IT IS ESCAPED (CLOUD-1445). Both rows below
# read `budgets[id]` as `budgets` followed by one character from {i,d}, which
# occurs nowhere in this file — so `sed` matched nothing, the staged copy came out
# byte-identical, and the first sweep reported `inert-mutation`: a gate listed in
# `$MUTANT_GATES`, reading as covered, that had never tested one byte of behaviour.
#
# THE THIRD ROW IS THE CONTROL and is deliberately left as it is. It names no
# bracket, it applies, and it was the only one of the three the sweep did not
# report — which is what identifies the cause as the escaping rather than the
# predicate.
#MUTANT over-budget-passes|s@to_number(measured) > budgets\[id\]@false@|an_over_budget_path_is_refused
#MUTANT readme-budget-disagreement-passes|s@published\[id\] != budgets\[id\]@false@|a_readme_publishing_a_different_budget_is_refused
#MUTANT absent-budgeted-path-passes|s@not id in object.keys(judged)@false@|a_budgeted_path_absent_from_a_present_record_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.perf_assert

import rego.v1

rules contains "perf-over-budget"

rules contains "perf-record-incomplete"

rules contains "perf-budget-unpublished"

rules contains "perf-budget-unreadable"

# The budgets, in milliseconds, written once here as data — the placement the
# predecessor's `BUDGETS` table had, one level over.
#
# A LITERAL IN A CONSUMER MODULE, NOT A `[[pattern]]` ROW. Non-negotiable rule 1
# scopes to `crates/batten`, and a `policy/*.rego` module IS consumer config, so a
# number is at home here exactly as it was at home in the shell table.
# `rules/policy-modules.md` refuses a threshold spelled as a pattern for
# the opposite reason — arithmetic is not a concept with one spelling — and this
# is not that.
#
# A path named here must appear in the record; a path in the record that is not
# named here is measured and not gated.
budgets := {
	"noop": 100,
	"passthrough": 100,
	"posttool": 100,
	"hook": 100,
	"wired": 100,
	"check": 100,
}

# The record ids this module owns.
#
# `input.tree["tool-verdict"]` is built from every `[[rule.tools]]` row in the
# config — the projection flattens across all rules — so a sibling row's record
# reaches this module too. `validator-verdict-clean` records the measured defect:
# `hk-plan`'s seven `<step> included` lines were read as seven findings by a
# module that did not name its ids. Named here for that reason.
owned := "perf-p95"

# What the producer recorded, or nothing.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a tool, and
# indexing into `null` is a hard evaluation FAULT in Rego rather than a silent
# miss.
#
# ABSENT IS NOT EMPTY, and the whole family turns on it. A record whose key does
# not resolve — no such tool version, or a binary rebuilt since the measurement —
# is absent from the map entirely, so every clause below abstains rather than
# reporting clean. A checkout that has never run `perf` is silent here, which is
# the honest answer and not a pass.
judged := measurements if {
	is_object(input.tree["tool-verdict"])
	measurements := input.tree["tool-verdict"][owned]
}

# --- the measurement half ----------------------------------------------------

# A budgeted path whose measured p95 is over its ceiling.
violation contains {
	"rule": "perf-over-budget",
	"verdict": "path measure late",
	"subjects": [{"count": count(over_budget)}],
} if {
	count(over_budget) > 0
}

over_budget contains id if {
	some id, measured in judged
	id in object.keys(budgets)
	to_number(measured) > budgets[id]
}

# A budgeted path the record does not carry.
#
# A run that measured five of six paths and reported green over the five is
# exactly the partial-coverage false green this repository keeps re-meeting, so
# absence within a PRESENT record is a finding. The guard is that `judged` itself
# must resolve: with no record at all there is nothing to be incomplete about.
violation contains {
	"rule": "perf-record-incomplete",
	"verdict": "path measure partial",
	"subjects": [{"count": count(unmeasured)}],
} if {
	count(unmeasured) > 0
}

unmeasured contains id if {
	is_object(judged)
	some id, _ in budgets
	not id in object.keys(judged)
}

# --- the README half ---------------------------------------------------------

# Every row of every Markdown table in README, as its cells.
#
# Backticks are stripped so a cell written as `` `noop` `` matches the id the
# record carries, which is what the predecessor's `gsub(/`/, "", line)` did.
table_rows := [cells |
	some line in input.tree.lines["README.md"]
	startswith(trim_space(line), "|")
	cells := split(replace(line, "`", ""), "|")
]

# The budget column's index, FOUND BY ITS HEADER and never by a fixed position.
#
# A column index hardcoded here is a coupling between this gate and the table's
# shape, so adding a column to the published table would silently start comparing
# the wrong cell — and comparing the wrong cell is how a gate reports a
# disagreement that is really its own arithmetic.
budget_column := index if {
	some cells in table_rows
	some index, cell in cells
	trim_space(cell) == "budget"
}

# The published budget per path id, for the rows that publish a number.
#
# A cell is written `≤ <n> ms` for a gated path and `—` for an ungated one, so the
# two states are distinguishable in the table itself. The number is taken as the
# cell's one numeric token rather than by stripping non-digits: `—` yields no such
# token and so is absent here, which is what lets an ungated row be told apart
# from a row publishing zero.
published[id] := budget if {
	some cells in table_rows
	id := trim_space(cells[1])
	id in object.keys(budgets)
	cell := trim_space(cells[budget_column])
	some token in split(cell, " ")
	regex.match(data.batten.patterns["published-budget-value"], token)
	budget := to_number(token)
}

# A budgeted path README publishes a different number for.
violation contains {
	"rule": "perf-budget-unpublished",
	"verdict": "prose state wrong",
	"subjects": [{"count": count(disagreeing)}],
} if {
	count(disagreeing) > 0
}

disagreeing contains id if {
	some id, _ in budgets
	id in object.keys(published)
	published[id] != budgets[id]
}

# A budgeted path README carries no numeric budget cell for at all — either no
# row, or a row publishing `—` while this module gates it.
disagreeing contains id if {
	some id, _ in budgets
	count(table_rows) > 0
	not id in object.keys(published)
}

# --- could not look ----------------------------------------------------------

# THE `missing` CLAUSE, and it is not optional. A module that iterates only what
# acquired reports green over a file it never read, and a dead gate and a clean
# tree are byte-identical on the decision surface. `NotAcquired` keeps the two
# causes apart deliberately, so this reports that it could not look rather than
# deciding.
violation contains {
	"rule": "perf-budget-unreadable",
	"verdict": "source read missing",
	"subjects": [{"path": "README.md"}],
} if {
	input.tree.missing["README.md"]
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE composes the record's
# key from a pinned tool and an input digest, or that it fills
# `input.tree.lines["README.md"]` at all — a `with input as` block writes the
# shape it then reads. `crates/batten/tests/it/perf_assert.rs` is the tier that
# drives the compiled binary, and it is where the `missing` clause is asserted for
# that reason.

# A README table publishing exactly what `budgets` enforces, so a case about the
# measurement half is not also a case about the README half.
agreeing_readme := [
	"| path | what it does | p50 | p95 | budget |",
	"| ---- | ------------ | --- | --- | ------ |",
	"| `noop` | process start | 2.1 ms | 2.4 ms | ≤ 100 ms |",
	"| `check` | one-rule tree | 2.3 ms | 2.7 ms | ≤ 100 ms |",
	"| `hook` | adjudication | 2.8 ms | 3.0 ms | ≤ 100 ms |",
	"| `passthrough` | a call no rule selects | — | — | ≤ 100 ms |",
	"| `posttool` | a PostToolUse call | — | — | ≤ 100 ms |",
	"| `wired` | as settings.json invokes it | 8.0 ms | 8.4 ms | ≤ 100 ms |",
]

# Every budgeted path measured, comfortably inside.
clean_record := {
	"noop": "2.4",
	"check": "2.7",
	"hook": "3.0",
	"passthrough": "2.2",
	"posttool": "2.3",
	"wired": "8.4",
}

test_a_measurement_inside_every_budget_is_silent if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {"perf-p95": clean_record},
	}}
}

test_an_over_budget_path_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {"perf-p95": object.union(clean_record, {"noop": "150"})},
	}}
}

# The p95 is fractional milliseconds, so the comparison has to be numeric rather
# than lexical — "99.5" sorts after "100" as a string.
test_a_fractional_p95_inside_its_budget_is_silent if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {"perf-p95": object.union(clean_record, {"noop": "99.5"})},
	}}
}

test_a_budgeted_path_absent_from_a_present_record_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {"perf-p95": object.remove(clean_record, {"wired"})},
	}}
}

# ABSENT IS NOT INCOMPLETE. A key that does not resolve — a differently pinned
# tool, or a binary rebuilt since the measurement — is not a partial record, and
# reading it as one would fail every checkout that has never run `perf`.
test_no_record_at_all_is_silent if {
	count(violation) == 0 with input as {"tree": {"lines": {"README.md": agreeing_readme}}}
}

# A record carrying a path this module does not budget is measured and not gated,
# which is what the predecessor's table said about `check` before it had a row.
test_an_unbudgeted_path_in_the_record_is_ignored if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {"perf-p95": object.union(clean_record, {"unbudgeted": "9000"})},
	}}
}

# A SIBLING ROW'S RECORD IS NOT THIS MODULE'S. `input.tree["tool-verdict"]` is
# flattened across every `[[rule.tools]]` row, so without `owned` this module
# would read another producer's lines as its own findings.
test_a_sibling_rows_record_is_not_read if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"README.md": agreeing_readme},
		"tool-verdict": {
			"perf-p95": clean_record,
			"hk-plan": {"some-step": "included"},
		},
	}}
}

test_a_readme_publishing_a_different_budget_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"README.md": array.concat(
			array.slice(agreeing_readme, 0, 2),
			array.concat(
				["| `noop` | process start | 2.1 ms | 2.4 ms | ≤ 50 ms |"],
				array.slice(agreeing_readme, 3, 8),
			),
		)},
		"tool-verdict": {"perf-p95": clean_record},
	}}
}

test_a_readme_with_no_row_for_a_budgeted_path_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"README.md": array.slice(agreeing_readme, 0, 7)},
		"tool-verdict": {"perf-p95": clean_record},
	}}
}

# THE UNGATED CELL IS THE DISAGREEMENT WRITTEN THE OTHER WAY ROUND. `—` publishes
# "not gated" while this module gates the path, and letting that pass is how the
# published column and the enforced table drift apart in the direction nobody
# notices.
test_a_readme_publishing_no_budget_for_a_gated_path_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"README.md": array.concat(
			array.slice(agreeing_readme, 0, 2),
			array.concat(
				["| `noop` | process start | 2.1 ms | 2.4 ms | — |"],
				array.slice(agreeing_readme, 3, 8),
			),
		)},
		"tool-verdict": {"perf-p95": clean_record},
	}}
}

# THE COLUMN IS FOUND BY ITS HEADER, so a table that grows a column still compares
# the right cell. A fixed index would silently start reading `p95` here.
test_a_reordered_budget_column_is_still_found if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"README.md": [
			"| path | budget | p50 | p95 |",
			"| ---- | ------ | --- | --- |",
			"| `noop` | ≤ 100 ms | 2.1 ms | 2.4 ms |",
			"| `check` | ≤ 100 ms | 2.3 ms | 2.7 ms |",
			"| `hook` | ≤ 100 ms | 2.8 ms | 3.0 ms |",
			"| `passthrough` | ≤ 100 ms | — | — |",
			"| `posttool` | ≤ 100 ms | — | — |",
			"| `wired` | ≤ 100 ms | 8.0 ms | 8.4 ms |",
		]},
		"tool-verdict": {"perf-p95": clean_record},
	}}
}

test_an_unreadable_readme_is_reported if {
	count(violation) == 1 with input as {"tree": {"missing": {"README.md": "absent"}}}
}
