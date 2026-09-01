#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT program-unread|s@^\tsegment.words\[0\] == "git"$@\tfalse@|the_commit_hygiene_preset_decides_both_ways
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
	"verdict": "V-EMPTY-COMMIT",
} if {
	# PER SEGMENT (CLOUD-857), the identical anchoring defect its sibling
	# `no-force-push` carried: `split(input.call.command, " ")` asks about the
	# first word of the LINE, so `cd /tmp && git commit --allow-empty` was
	# allowed. `input.call.segments` is `hook::segments` projected — the one
	# parser — and no `split` belongs here.
	some segment in input.call.segments
	segment.words[0] == "git"
	"commit" in segment.words
	"--allow-empty" in segment.words
}

# The predicate's own tests (CLOUD-835). The negative cases are what make this a
# test of the practice rather than of the string: an ordinary commit and another
# tool's `--allow-empty` both have to stay unjudged.
#
# Every case passes segments and one is COMPOUND (CLOUD-857): a bare-only suite
# is exactly what let the anchoring defect above ship green, and `batten policy
# test` reports one now.
test_no_empty_commit if {
	some v in violation with input as {"call": {"segments": [{"words": ["git", "commit", "--allow-empty", "-m", "x"], "raw": "git commit --allow-empty -m x", "terminator": null}]}}
	v.rule == "no-empty-commit"
}

test_an_empty_commit_later_in_a_list_is_caught if {
	some v in violation with input as {"call": {"segments": [
		{"words": ["cd", "/tmp"], "raw": "cd /tmp", "terminator": "&&"},
		{"words": ["git", "commit", "--allow-empty", "-m", "x"], "raw": "git commit --allow-empty -m x", "terminator": null},
	]}}
	v.rule == "no-empty-commit"
}

test_an_ordinary_commit_is_left_alone if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["git", "commit", "-m", "x"], "raw": "git commit -m x", "terminator": null}]}}
}

# A quoted mention stays one word (CLOUD-269), so the program is `echo`.
test_a_quoted_mention_does_not_fire if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["echo", "git commit --allow-empty"], "raw": "echo \"git commit --allow-empty\"", "terminator": null}]}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["hg", "commit", "--allow-empty"], "raw": "hg commit --allow-empty", "terminator": null}]}}
}
