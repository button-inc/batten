#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT program-unread|s@^\tprogram.name == "git"$@\tfalse@|the_commit_hygiene_preset_decides_both_ways
# Commit hygiene: a commit records a change, and an empty one records that
# somebody wanted a new SHA.
#
# The reachable use is kicking a pipeline, which is why this is a practice-level
# predicate rather than a style preference: an empty commit spends a CI run to
# re-ask a question the previous run already answered, and it puts a commit in
# the history that no reader can act on.
#
# Names no repository, no ref and no task (non-negotiable rule 1).
package batten.commit_hygiene

import rego.v1

rules contains "no-empty-commit"

violation contains {
	"rule": "no-empty-commit",
	"verdict": "commit ship empty",
} if {
	# ON THE PROGRAM (CLOUD-1382), and this module has now carried its sibling
	# `no-force-push`'s anchoring defect twice, which is why the history is kept
	# rather than tidied.
	#
	# First it read `split(input.call.command, " ")` — the first word of the
	# LINE — so `cd /tmp && git commit --allow-empty` was allowed (CLOUD-857).
	# Then it read `segment.words[0]`, which is the first word of the SEGMENT and
	# still not the program: `(git commit --allow-empty …)`, `time …`, `! …`,
	# `{ …; }` and `command …` each put a token at index 0 and each runs the
	# commit. Measured on the sibling, one keystroke apiece.
	#
	# `input.call.programs` is the argv the engine already read (CLOUD-1028), and
	# `arguments` is what THIS program was handed — so `--allow-empty` is
	# correlated with git's own invocation rather than with the line it sits on.
	# No `split` belongs here: a second tokenizer is a second authority.
	some program in input.call.programs
	program.name == "git"
	"commit" in program.arguments
	"--allow-empty" in program.arguments
}

# The predicate's own tests (CLOUD-835). The negative cases are what make this a
# test of the practice rather than of the string: an ordinary commit and another
# tool's `--allow-empty` both have to stay unjudged.
#
# Every case passes `programs` and one is COMPOUND (CLOUD-857): a bare-only
# suite is exactly what let the first anchoring defect ship green.
#
# AND HAND-WRITTEN `programs` IS STILL NOT THE ENGINE'S, which is why
# `#MUTANT-SUITE` names a compiled tier. A case here supplies the resolution
# under test — it cannot say whether the boundary resolves `(git` to `git`, only
# that the predicate would be right if it did. That is what let CLOUD-1382's six
# bypasses sit under a green suite.
test_no_empty_commit if {
	some v in violation with input as {"call": {"programs": [{"program": "git", "name": "git", "arguments": ["commit", "--allow-empty", "-m", "x"], "mediated": false}]}}
	v.rule == "no-empty-commit"
}

test_an_empty_commit_later_in_a_list_is_caught if {
	some v in violation with input as {"call": {"programs": [
		{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false},
		{"program": "git", "name": "git", "arguments": ["commit", "--allow-empty", "-m", "x"], "mediated": false},
	]}}
	v.rule == "no-empty-commit"
}

# The grammar case (CLOUD-1382): the caller wrote `time git commit
# --allow-empty`, and the walk steps past `time`, so the entry names git.
test_a_grammar_token_does_not_hide_the_program if {
	some v in violation with input as {"call": {"programs": [{"program": "git", "name": "git", "arguments": ["commit", "--allow-empty"], "mediated": false}]}}
	v.rule == "no-empty-commit"
}

# Reached through a path, still git — what `name` buys over `program`.
test_git_reached_through_a_path_is_still_git if {
	some v in violation with input as {"call": {"programs": [{"program": "/usr/bin/git", "name": "git", "arguments": ["commit", "--allow-empty"], "mediated": false}]}}
	v.rule == "no-empty-commit"
}

test_an_ordinary_commit_is_left_alone if {
	count(violation) == 0 with input as {"call": {"programs": [{"program": "git", "name": "git", "arguments": ["commit", "-m", "x"], "mediated": false}]}}
}

# A quoted mention stays one word (CLOUD-269), so the program is `echo`.
test_a_quoted_mention_does_not_fire if {
	count(violation) == 0 with input as {"call": {"programs": [{"program": "echo", "name": "echo", "arguments": ["git commit --allow-empty"], "mediated": false}]}}
}

# THE FLAG MUST BE THIS PROGRAM'S. git is invoked and `--allow-empty` is on the
# line; they are not the same invocation, and anchoring on the program while
# reading the flag from anywhere would be the defect one level up.
test_another_programs_flag_is_not_gits if {
	count(violation) == 0 with input as {"call": {"programs": [
		{"program": "git", "name": "git", "arguments": ["commit", "-m", "x"], "mediated": false},
		{"program": "hg", "name": "hg", "arguments": ["commit", "--allow-empty"], "mediated": false},
	]}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"programs": [{"program": "hg", "name": "hg", "arguments": ["commit", "--allow-empty"], "mediated": false}]}}
}
