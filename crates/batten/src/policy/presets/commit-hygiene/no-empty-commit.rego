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
