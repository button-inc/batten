# METADATA
# description: |
#   Under `set -o pipefail`, no shell program pipes a producer into an
#   early-exiting `grep` — ported from `mise-tasks/pipefail-grep-check.sh` under
#   CLOUD-843.
#
#   `producer | grep -q PATTERN` under pipefail can return FAILURE on a match.
#   grep exits the moment it finds the first hit; if the producer is still
#   writing it dies of SIGPIPE, and pipefail promotes that signal (141) to the
#   pipeline's status. So the SUCCESSFUL case is the one that reports failure.
#
#   It is a RACE, which is what lets it survive review and a green suite:
#   measured on a two-commit range, 2 failures in 300 runs. A large producer
#   loses nearly always; a small one loses rarely, passes every test written for
#   it, and denies someone months later. Two instances landed here before the
#   class was named — `landed-check` reported a CLEAN BOARD over three issues
#   whose refs were on main, and `issue-guard` DENIED `gh pr ready` on a branch
#   where every commit carried its key, with a reason stating the opposite of
#   what it had just found. Both fail toward the verdict nobody checks.
#
#   THE FIX NEEDS NO NEW TOOL and is always the same shape: read the producer
#   into a variable and match from a here-string, which has no upstream process
#   and so no status to promote.
#
#   SCOPE, DELIBERATELY. Only files that actually enable pipefail, and only the
#   early-exiting forms — `-q`, `-l` (stops at the first matching file) and
#   `-m N`. A plain `| grep` consumes its whole input, so the producer never
#   takes SIGPIPE and the pipeline's status is honest.
#
#   THE CLUSTER IS READ LETTER BY LETTER rather than enumerated, and that is the
#   predecessor's decision carried rather than its spelling. `-qxF` and `-oq` are
#   the same hazard as `-q`, so the test is "a short-flag cluster containing q or
#   l" — an enumeration of exact spellings is what would rot.
#
#   `--` ENDS THE FLAGS. `grep -- -q` is searching for the literal `-q`, not
#   asking to be quiet, and the predecessor stopped its scan there for that
#   reason.
#
#   Output is a pointer (non-negotiable rule 4): `path:line` and the fix, never
#   the matched content.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.pipefail_grep

import rego.v1

rules contains "spawn read broken"

# Files that actually turn pipefail on. Everything else is out of scope, because
# without it a SIGPIPE never reaches the pipeline's status.
enables_pipefail(path) if {
	some line in input.tree.lines[path]
	regex.match(data.batten.patterns["shell-enables-pipefail"], line)
}

# A line that pipes into grep, in a file that enables pipefail, and is not a
# comment describing the hazard.
candidate contains [path, index, line] if {
	some path, file_lines in input.tree.lines
	enables_pipefail(path)
	some index, line in file_lines
	not startswith(trim_space(line), "#")
	regex.match(data.batten.patterns["pipe-into-grep"], line)
}

# **THE SEGMENT IS BOUNDED BY THE PIPE ITSELF** (review of #928), which is what
# makes this read grep's flags and only grep's.
#
# This was `split(line, "| grep")` and took everything after the last match to
# the END OF LINE, so `producer | grep pattern | wc -l` handed `flag_tokens` the
# text ` pattern | wc -l` and `-l` — `wc`'s flag — read as an early-exit grep
# flag. A false violation on a `deny` row, which is the direction that gets a
# gate switched off.
#
# It also missed `producer |  grep -q thing`: splitting on the literal `"| grep"`
# cannot see two spaces, while `pipe-into-grep` — the pattern that decides
# whether a line is a candidate at all — accepts any whitespace. So `candidate`
# fired, `piped_flags` went undefined, and the violation silently did not.
# Splitting on `|` and testing each stage fixes both with one predicate.
stages(line) := split(line, "|")

# The LAST stage that invokes grep. Last rather than first for the reason the old
# comment gave: an earlier `grep` in the pipeline has its own flags, and it is
# the one being piped INTO whose early exit breaks the producer.
#
# THE RESIDUE IS A PIPE INSIDE A QUOTED STRING, named rather than silent: a
# pattern like `grep 'a|b'` splits here into stages that are not stages. It lands
# in the UNDER-deny direction — the fragment does not start with `grep`, so it is
# not read as one — which is the same direction the module's `-- ` clause below
# already chooses.
grep_stage(line) := stage if {
	found := [candidate_stage |
		some candidate_stage in stages(line)
		invokes_grep(candidate_stage)
	]
	count(found) > 0
	stage := found[count(found) - 1]
}

invokes_grep(stage) if startswith(trim_space(stage), "grep ")

invokes_grep(stage) if trim_space(stage) == "grep"

# The tokens before `--`, which ends the flags: `grep -- -q` searches for the
# literal `-q`.
flag_tokens(line) := tokens if {
	before := split(grep_stage(line), " -- ")[0]
	tokens := [token |
		some token in split(before, " ")
		token != ""
		token != "grep"
	]
}

# A long flag that exits early.
early(token) if token == "--quiet"

early(token) if token == "--files-with-matches"

early(token) if startswith(token, "--max-count")

early(token) if startswith(token, "-m")

# A SHORT-FLAG CLUSTER carrying `q` or `l` anywhere in it. Letter by letter, so
# `-qxF` and `-oq` are the same hazard as `-q` without enumerating spellings.
early(token) if {
	startswith(token, "-")
	not startswith(token, "--")
	some letter in split(substring(token, 1, -1), "")
	letter in {"q", "l"}
}

violation contains {
	"rule": "spawn read broken",
	"verdict": "spawn read broken",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some [path, index, line] in candidate
	some token in flag_tokens(line)
	early(token)
}

# --- the load-time tier ------------------------------------------------------

scan(ls) := {"tree": {"lines": {"mise-tasks/demo.sh": array.concat(["set -euo pipefail"], ls)}}}

test_the_shape_that_broke_issue_guard_is_flagged if {
	some v in violation with input as scan(["git log --format=%B main | grep -q \"$id\""])
	v.verdict == "spawn read broken"
}

test_the_here_string_fix_passes if {
	count(violation) == 0 with input as scan(["x=$(git log); grep -q \"$id\" <<<\"$x\""])
}

test_a_flag_cluster_is_judged_by_its_letters if {
	count(violation) == 1 with input as scan(["producer | grep -qxF thing"])
}

test_long_names_are_the_same_hazard if {
	count(violation) == 2 with input as scan([
		"producer | grep --quiet thing",
		"producer | grep --files-with-matches thing",
	])
}

test_a_grep_that_consumes_its_whole_input_is_not_the_hazard if {
	count(violation) == 0 with input as scan(["producer | grep thing"])
}

# **A LATER STAGE'S FLAGS ARE NOT GREP'S** (review of #928). The segment used to
# run to the end of the line, so `wc -l` here supplied an `-l` that read as an
# early-exit grep flag — a false violation on a `deny` row, which is the
# direction that gets a gate switched off rather than fixed.
test_a_flag_belonging_to_a_later_stage_is_not_greps if {
	count(violation) == 0 with input as scan(["producer | grep thing | wc -l"])
}

# AND THE GREP BEING PIPED INTO IS STILL JUDGED when a later stage follows it, so
# the bound above is not a way to pass by appending one.
test_an_early_exit_is_still_caught_with_a_later_stage if {
	count(violation) == 1 with input as scan(["producer | grep -q thing | wc -l"])
}

# WHITESPACE AFTER THE PIPE IS WHITESPACE. `pipe-into-grep` accepts it when
# deciding a line is a candidate, so a segment reader that could not see it made
# the candidate decide nothing — fired, then went undefined, then reported clean.
test_extra_space_after_the_pipe_is_still_a_pipe_into_grep if {
	count(violation) == 1 with input as scan(["producer |  grep -q thing"])
}

# THE EARLIER GREP IS NOT THE ONE THAT MATTERS: its own early exit breaks the
# stage before it, but the hazard this rule names is the LAST one, whose exit
# SIGPIPEs the producer the caller is reading.
test_the_last_grep_is_the_one_judged if {
	count(violation) == 0 with input as scan(["producer | grep -q first | grep second"])
}

# `||` IS NOT A PIPE, and this is the case the predecessor's own scan failed:
# it matched the second bar and reported the recommended remedy as the defect.
test_an_or_before_grep_is_not_a_pipe if {
	count(violation) == 0 with input as scan(["[[ -n \"$x\" ]] || grep -qE 'p' <<<\"$var\""])
}

test_q_after_the_separator_is_a_pattern_not_a_flag if {
	count(violation) == 0 with input as scan(["producer | grep -- -q"])
}

test_a_file_that_does_not_enable_pipefail_is_out_of_scope if {
	count(violation) == 0 with input as {"tree": {"lines": {"mise-tasks/demo.sh": ["producer | grep -q thing"]}}}
}

test_a_comment_describing_the_hazard_is_not_the_hazard if {
	count(violation) == 0 with input as scan(["# never write producer | grep -q thing"])
}

#MUTANT-SUITE crates/batten/tests/it/pipefail_grep.rs
#MUTANT pipefail-cluster-unread|s@letter in {"q", "l"}@false@|a_flag_cluster_is_judged_by_its_letters_over_the_binary
#MUTANT pipefail-or-is-a-pipe|s@data.batten.patterns\["pipe-into-grep"\]@"grep"@|an_or_before_grep_is_not_a_pipe
#MUTANT pipefail-scope-unread|s@enables_pipefail(path)$@true@|a_file_that_does_not_enable_pipefail_is_out_of_scope
