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
	"msg": "an empty commit records no change; if the goal is a fresh run, re-run the pipeline rather than minting a SHA nobody can read",
} if {
	words := split(input.call.command, " ")
	words[0] == "git"
	"commit" in words
	"--allow-empty" in words
}

# The predicate's own tests (CLOUD-835). The negative cases are what make this a
# test of the practice rather than of the string: an ordinary commit and another
# tool's `--allow-empty` both have to stay unjudged.
test_no_empty_commit if {
	some v in violation with input as {"call": {"command": "git commit --allow-empty -m x"}}
	v.rule == "no-empty-commit"
}

test_an_ordinary_commit_is_left_alone if {
	count(violation) == 0 with input as {"call": {"command": "git commit -m x"}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"command": "hg commit --allow-empty"}}
}
