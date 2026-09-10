# METADATA
# description: |
#   The per-suite cost corpus names every tracked bats suite and only real ones —
#   CLOUD-352, ported from `mise-tasks/suite-bench-check.sh` under CLOUD-1753.
#
#   WHAT THIS DECIDES AND DELIBERATELY DOES NOT. `bench/suites/RESULTS.md` records
#   how long each suite takes, written by `batten record suites` from the report
#   the runner leaves behind. It is NOT byte-diffed against a fresh run, and that
#   is the whole design decision rather than a gap. Token counts are
#   deterministic — the same fixtures yield the same numbers on any machine — so
#   the token corpus CAN be diffed. Wall clock cannot: the same suite varies with
#   load, and a gate demanding byte equality on a duration would be red on every
#   second run and switched off within a day. `rules/toolchain.md` puts a clock in
#   a drift job rather than in a gate.
#
#   WHAT IS DETERMINISTIC IS MEMBERSHIP, and membership is what rots. A suite
#   added and never recorded is invisible to everything reading the corpus; a row
#   naming a suite that was deleted is a figure attached to nothing. Both are
#   decidable from committed text at no runtime cost, and both are what make the
#   corpus trustworthy enough to answer the question an author actually asks: is
#   the file I am about to add a case to expensive?
#
#   THE CORPUS IS A CONTRACT BETWEEN TWO HALVES, which is why the path is spelled
#   in `crates/batten/src/suites.rs` as `CORPUS` and here as a `lines` source. The
#   producer writes those bytes and this reads them; a port that let either half
#   pick its own location would have silently disconnected them.
#
#   ANTI-VACUITY IN BOTH DIRECTIONS. An absent corpus is could-not-look, never a
#   clean tree — the whole point is that nothing records the cost. A tree with no
#   tracked suites is also could-not-look rather than a clean corpus: the corpus
#   would have no subject, and reporting green over that is the CLOUD-251 collapse
#   this repository keeps meeting in new disguises.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the suite and which direction
#   failed. Never a duration — a number emitted here would be a second authority
#   over the corpus, which is exactly what the producer is for.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.suite_cost_corpus

import rego.v1

rules contains "suite-cost-corpus"

corpus_path := "bench/suites/RESULTS.md"

corpus_lines := lines if {
	lines := input.tree.lines[corpus_path]
}

# --- the two sets --------------------------------------------------------------

# The tracked suites, from the INDEX rather than a directory walk: an untracked
# scratch file beside the suites is not something the corpus should have to carry,
# and a walk would put it there. `input.tree.tracked` is `git ls-files`' own
# membership test, which is what the retired program used.
tracked contains path if {
	some path in input.tree.tracked
	startswith(path, "tests/")
	endswith(path, ".bats")
}

# The corpus rows: the path inside the third column's backticks.
#
# READ AS TEXT AND TOLERANT OF PADDING, which is not cosmetic. `prettier` owns
# Markdown here and aligns table columns; the retired program's first pattern
# required exactly one space before the closing pipe, matched no row at all
# against a formatted corpus, and reported every tracked suite as missing — 150
# findings, all false, from a gate that looked like it was working.
recorded contains suite if {
	some line in corpus_lines
	parts := split(line, "|")
	count(parts) >= 4
	cell := trim_space(parts[3])
	startswith(cell, "`")
	endswith(cell, "`")
	suite := trim(cell, "`")
	suite != ""
}

# --- could not look ------------------------------------------------------------

violation contains {
	"rule": "suite-cost-corpus",
	"verdict": "suite count unread",
	"subjects": [{"path": corpus_path}],
} if {
	not corpus_lines
}

violation contains {
	"rule": "suite-cost-corpus",
	"verdict": "suite count unread",
	"subjects": [{"path": corpus_path}],
} if {
	corpus_lines
	count(recorded) == 0
}

# A tree with no tracked suites gives the corpus no subject. Conditioned on the
# tracked fact having resolved at all, so this does not fire in a consumer tree
# that carries no bats — the scoping defect CLOUD-1164 records for `tree-clean`,
# avoided rather than survived.
violation contains {
	"rule": "suite-cost-corpus",
	"verdict": "suite list empty",
	"subjects": [{"count": 0}],
} if {
	corpus_lines
	input.tree.tracked
	count(tracked) == 0
}

# --- the two directions --------------------------------------------------------

violation contains {
	"rule": "suite-cost-corpus",
	"verdict": "suite count absent",
	"subjects": [{"path": suite}],
} if {
	count(recorded) > 0
	some suite in tracked
	not suite in recorded
}

violation contains {
	"rule": "suite-cost-corpus",
	"verdict": "suite count dead",
	"subjects": [{"path": row}],
} if {
	count(tracked) > 0
	some row in recorded
	not row in tracked
}

# --- the load-time tier --------------------------------------------------------
#
# These pin the PREDICATE — the row parse and the two directions. They cannot pin
# that the ENGINE resolves the declared `lines` path to the committed bytes, nor
# that `input.tree.tracked` is the index rather than a walk (CLOUD-845).
# `crates/batten/tests/it/suite_cost_corpus.rs` is that tier.

# THE KEY IS A LITERAL, and that is not style. Written as `{corpus_path: …}` — a
# rule reference in key position — the fixture built an object this module's own
# `input.tree.lines[corpus_path]` did not resolve against, so `corpus_lines` was
# wrong in every case that used it. The three "clean" cases still passed, because
# a fixture that resolves to nothing produces no findings and reads exactly like
# a clean tree. That is the load-time tier's own version of the failure it exists
# to catch, and it took probe cases to see: `tracked` resolved and `corpus_lines`
# did not, from the same object literal.
#
# Every working fixture in `policy/` spells the key literally for this reason.
fixture(rows, files) := {"tree": {
	"lines": {"bench/suites/RESULTS.md": array.concat(
		["# Per-suite cost of `test:bats`", "", "| seconds | share | suite |", "| ---: | ---: | --- |"],
		rows,
	)},
	"tracked": files,
}}

test_a_corpus_naming_exactly_the_tracked_suites_is_clean if {
	count(violation) == 0 with input as fixture(
		["| 4.5 | 90.0% | `tests/slow.bats` |", "| 0.5 | 10.0% | `tests/quick.bats` |"],
		["tests/slow.bats", "tests/quick.bats"],
	)
}

test_a_tracked_suite_with_no_row_is_refused if {
	some v in violation with input as fixture(
		["| 4.5 | 100.0% | `tests/slow.bats` |"],
		["tests/slow.bats", "tests/unrecorded.bats"],
	)
	v.verdict == "suite count absent"
}

test_a_row_naming_no_tracked_suite_is_refused if {
	some v in violation with input as fixture(
		["| 4.5 | 50.0% | `tests/slow.bats` |", "| 4.5 | 50.0% | `tests/retired.bats` |"],
		["tests/slow.bats"],
	)
	v.verdict == "suite count dead"
}

# PADDING IS TOLERATED, and the retired program's own measurement is why: a
# formatter that aligns the columns must not make the gate report every suite
# missing.
test_an_aligned_row_still_resolves if {
	count(violation) == 0 with input as fixture(
		["|   4.5 |  100.0% | `tests/slow.bats`   |"],
		["tests/slow.bats"],
	)
}

test_an_absent_corpus_is_could_not_look if {
	some v in violation with input as {"tree": {"lines": {}, "tracked": ["tests/slow.bats"]}}
	v.verdict == "suite count unread"
}

test_a_corpus_with_no_rows_is_could_not_look if {
	some v in violation with input as fixture([], ["tests/slow.bats"])
	v.verdict == "suite count unread"
}

# A tree with no suites gives the corpus no subject, which is not the same answer
# as a corpus that covers every suite there is.
test_a_tree_with_no_tracked_suite_is_could_not_look if {
	some v in violation with input as fixture(["| 1.0 | 100.0% | `tests/x.bats` |"], [])
	v.verdict == "suite list empty"
}

# Only `tests/*.bats` is the corpus's subject: a tracked file elsewhere is not a
# suite and must not be reported as an unrecorded one.
test_a_tracked_non_suite_is_not_the_corpus_subject if {
	count(violation) == 0 with input as fixture(
		["| 4.5 | 100.0% | `tests/slow.bats` |"],
		["tests/slow.bats", "crates/batten/src/lib.rs", "tests/helpers.bash"],
	)
}

#MUTANT-SUITE crates/batten/tests/it/suite_cost_corpus.rs
#MUTANT unrecorded-suite-admitted|s@^\tnot suite in recorded$@\tfalse@|a_tracked_suite_with_no_row_is_refused
#MUTANT phantom-row-admitted|s@^\tnot row in tracked$@\tfalse@|a_row_naming_no_tracked_suite_is_refused
#MUTANT absent-corpus-read-as-clean|s@^\tnot corpus_lines$@\tfalse@|an_absent_corpus_is_could_not_look
