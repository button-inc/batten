# METADATA
# description: |
#   The Rust workflow's `paths:` filter selects every input its jobs read, and
#   does not select a docs-only diff — CLOUD-398, ported from
#   `mise-tasks/rust-paths-check.sh` under CLOUD-843.
#
#   That workflow carries a workflow-level filter so a diff that cannot change its
#   verdicts creates no check run at all — ABSENT, which the required-checks reader
#   accepts, rather than `skipped`, which reads as no answer and makes the landing
#   loop poll forever.
#
#   THE FAILURE THIS EXISTS FOR IS SILENT IN THE DANGEROUS DIRECTION. A filter that
#   selects too widely costs money and is obvious in the bill. A filter that selects
#   too NARROWLY does not fail: the jobs are simply absent, the green-check reader
#   accepts absent by design, the branch lands, and a platform regression reaches
#   the trunk with every required check green. Nothing else in this repository would
#   notice. That asymmetry is why the glob ships with a gate over its own honesty
#   rather than with a comment claiming it is right — the shape CLOUD-224 set for
#   gate globs, applied to the one glob that decides whether a job runs at all.
#
#   WHAT IS AND IS NOT DECIDABLE HERE. "Which files does a job read" is not
#   computable from committed text — a task can shell out to anything. So this does
#   not derive the list. It fixes the CLAIMS the filter makes, as PROBES, and
#   decides whether the committed filter honours them: paths a change to which must
#   re-run these jobs, and paths a change to which must not. Adding a job with a new
#   input means adding its probe here, in the same commit, which is the same bargain
#   the step-receipt spec table makes.
#
#   THE MATCHER REFUSES WHAT IT CANNOT DECIDE rather than guessing. A `?`, a
#   bracketed class, a `*` in the middle and a leading negation all change selection
#   in ways a prefix test gets wrong — and getting one wrong here is exactly the
#   silent false-absent this exists to stop. An operator adding such a pattern
#   should have to extend the matcher in the same commit.
#
#   THE EMPTY PREFIX IS ITS OWN CASE, and it is not pedantry: a bare `**` strips to
#   nothing, so a naive "did the prefix strip anything" test reads it as matching
#   NOTHING, and a filter selecting the entire repository would pass as narrow. The
#   retiring program's docs-only probe caught that on its first run.
#
#   ANTI-VACUITY: a workflow with no `paths:` block runs on every pull request —
#   expensive, but SAFE — and reading that as "every probe honoured" would be
#   reporting on a filter that does not exist.
#
#   THE PREDICATE IS THIS CONSUMER'S. Which workflow carries the filter, and which
#   paths its jobs read, are facts about this consumer — non-negotiable rule 1.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the probe path and the verdict
#   that disagreed. Never the diff, never a file's contents.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.rust_paths_check

import rego.v1

rules contains "rust-paths-check"

workflow_path := ".github/workflows/rust.yml"

# MUST SELECT: an input a change to which can move one of the jobs' verdicts.
#
# The crate tree and the two manifests are what they compile; the toolchain file
# is the compiler they compile with; the dependency policy is what the audit job
# decides from; and the task manifest and its lock define and pin the tasks the
# jobs actually invoke — the input a filter written from "the Rust tree" is most
# likely to miss.
must_select := {
	"crates/batten/src/lib.rs",
	"Cargo.toml",
	"Cargo.lock",
	"rust-toolchain.toml",
	"deny.toml",
	"mise.toml",
	"mise.lock",
	".github/workflows/rust.yml",
}

# MUST NOT SELECT: a diff these jobs cannot be affected by. This is the half that
# pays for the split, and the half that erodes silently — every widening of the
# filter is invisible except as a bill.
must_not_select := {
	"README.md",
	"AGENTS.md",
	".claude/rules/rust.md",
	".serena/memories/core.md",
}

workflow_lines := lines if {
	lines := input.tree.lines[workflow_path]
}

# --- the committed filter ----------------------------------------------------
#
# A block sequence under a `paths:` key; each entry is a quoted or bare scalar on
# its own line. Read as text rather than through a document parser for the reason
# the retiring program gave: the shape is fixed by this repository's own file, and
# a parser is a dependency this judgement does not otherwise need.
paths_start := i if {
	some i, line in workflow_lines
	trim_space(line) == "paths:"
}

# The sequence ends at the first line after it that is not an entry.
entry_index contains j if {
	some j, line in workflow_lines
	j > paths_start
	startswith(trim_space(line), "- ")
	all_entries_contiguous_to(j)
}

all_entries_contiguous_to(j) if {
	every k in numbers.range(paths_start + 1, j) {
		startswith(trim_space(workflow_lines[k]), "- ")
	}
}

pattern contains value if {
	some j in entry_index
	raw := trim_space(substring(trim_space(workflow_lines[j]), 2, -1))
	value := trim(raw, "\"'")
	value != ""
}

# --- the matcher -------------------------------------------------------------

# The trailing star, stripped once. `**` first, so a two-star suffix yields the
# directory rather than a one-star remnant.
prefix_of(p) := substring(p, 0, count(p) - 2) if {
	endswith(p, "**")
}

prefix_of(p) := substring(p, 0, count(p) - 1) if {
	not endswith(p, "**")
	endswith(p, "*")
}

# A shape whose selection a prefix test gets wrong.
undecidable(p) if {
	some character in {"!", "?", "["}
	contains(p, character)
}

# A star anywhere but the end: whatever remains after stripping the suffix must
# carry none.
undecidable(p) if {
	prefix_of(p)
	contains(prefix_of(p), "*")
}

undecidable(p) if {
	not prefix_of(p)
	contains(p, "*")
}

# A literal pattern selects exactly itself.
selects(p, path) if {
	not prefix_of(p)
	not undecidable(p)
	p == path
}

# A prefix pattern selects everything beneath it — and the EMPTY prefix selects
# the entire repository, which is the case a "did the strip change anything" test
# reads backwards.
selects(p, path) if {
	not undecidable(p)
	prefix_of(p) == ""
}

selects(p, path) if {
	not undecidable(p)
	prefix_of(p) != ""
	startswith(path, prefix_of(p))
}

selected(path) if {
	some p in pattern
	selects(p, path)
}

# --- the findings ------------------------------------------------------------

# ANTI-VACUITY. A workflow with no filter is safe and expensive; reading it as
# "every probe honoured" reports on a filter that does not exist.
violation contains {
	"rule": "rust-paths-check",
	"verdict": "workflow read unclear",
	"subjects": [{"path": workflow_path}],
} if {
	workflow_lines
	count(pattern) == 0
}

violation contains {
	"rule": "rust-paths-check",
	"verdict": "workflow read unclear",
	"subjects": [{"artifact": p}],
} if {
	some p in pattern
	undecidable(p)
}

violation contains {
	"rule": "rust-paths-check",
	"verdict": "input select missing",
	"subjects": [{"path": probe}],
} if {
	count(pattern) > 0
	some probe in must_select
	not selected(probe)
}

violation contains {
	"rule": "rust-paths-check",
	"verdict": "input select loose",
	"subjects": [{"path": probe}],
} if {
	some probe in must_not_select
	selected(probe)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE — the matcher and the two probe sets. They cannot pin
# that the ENGINE resolves a declared `line_sources` path to the committed bytes
# of the workflow (CLOUD-845). `crates/batten/tests/it/rust_paths_check.rs` is
# that tier.

flow(entries) := {"tree": {"lines": {".github/workflows/rust.yml": array.concat(
	array.concat(["on:", "  pull_request:", "    paths:"], entries),
	["jobs:", "  build:"],
)}}}

honest := [
	"      - \"crates/**\"",
	"      - \"Cargo.toml\"",
	"      - \"Cargo.lock\"",
	"      - \"rust-toolchain.toml\"",
	"      - \"deny.toml\"",
	"      - \"mise.toml\"",
	"      - \"mise.lock\"",
	"      - \".github/workflows/rust.yml\"",
]

test_a_filter_honouring_every_probe_is_clean if {
	count(violation) == 0 with input as flow(honest)
}

# THE SILENT DIRECTION: dropping an input leaves the jobs absent, and absent is
# accepted by design.
test_a_dropped_input_is_refused if {
	some v in violation with input as flow(array.concat(array.slice(honest, 0, 5), array.slice(honest, 6, 8)))
	v.verdict == "input select missing"
}

test_a_docs_only_path_being_selected_is_refused if {
	some v in violation with input as flow(array.concat(honest, ["      - \"AGENTS.md\""]))
	v.verdict == "input select loose"
}

# A bare `**` strips to nothing. A "did the strip change anything" test reads that
# as matching NOTHING, so a filter selecting the whole repository passes as narrow.
test_a_whole_repository_glob_is_refused if {
	some v in violation with input as flow(["      - \"**\""])
	v.verdict == "input select loose"
}

test_a_workflow_with_no_paths_block_is_could_not_look if {
	some v in violation with input as {"tree": {"lines": {".github/workflows/rust.yml": ["on:", "  pull_request:", "jobs:"]}}}
	v.verdict == "workflow read unclear"
}

# A shape the matcher cannot decide is refused rather than guessed: a wrong answer
# here is the silent false-absent the whole gate exists to stop.
test_a_negation_is_refused_rather_than_guessed if {
	some v in violation with input as flow(array.concat(honest, ["      - \"!docs/**\""]))
	v.verdict == "workflow read unclear"
}

test_a_star_in_the_middle_is_refused_rather_than_guessed if {
	some v in violation with input as flow(array.concat(honest, ["      - \"crates/*/src\""]))
	v.verdict == "workflow read unclear"
}

#MUTANT-SUITE crates/batten/tests/it/rust_paths_check.rs
#MUTANT narrow-filter-passes|s@^\tnot selected(probe)$@\tfalse@|a_dropped_input_is_refused
#MUTANT wide-filter-passes|s@^\tselected(probe)$@\tfalse@|a_whole_repository_glob_is_refused
#MUTANT empty-prefix-read-as-no-match|s@^\tprefix_of(p) == ""$@\tfalse@|a_whole_repository_glob_is_refused
