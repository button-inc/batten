# `commit place wrong`: a merge commit made on a branch that lands by
# fast-forward into a linear history (CLOUD-2813).
#
# MEASURED on #1276. A push was rejected because the remote branch held commits
# this checkout lacked; the remedy taken was `git merge FETCH_HEAD`, three times,
# and one merge carried six conflict markers into a skill and was pushed. The
# history is linear by rule (`rules/commits.md`), and a rejected push is rebased
# onto what the remote holds, never merged with it. Nothing refused the merge:
# `linear-check` asks only whether the head contains `origin/main`.
#
# Refused: `git merge` unless `--ff-only` (or finishing/abandoning one in
# progress), and `git pull` unless it rebases or fast-forwards. The pre-push
# step `branch-linear` in `hk.pkl` is the backstop for a merge made any other way.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.merge_commit_linear

import rego.v1

rules contains "commit place wrong"

violation contains {
	"rule": "commit place wrong",
	"verdict": "commit place wrong",
	"subjects": [{"count": 1}],
} if {
	some program in input.call.programs
	program.name == "git"
	merges(program)
}

# `git merge X` makes a merge commit unless the branch fast-forwards, and only
# `--ff-only` guarantees that. Finishing or abandoning a merge already in
# progress makes none of its own choosing.
merges(program) if {
	program.subcommand == "merge"
	not "--ff-only" in program.arguments
	not "--abort" in program.arguments
	not "--quit" in program.arguments
	not "--continue" in program.arguments
}

# `git pull` merges by default; `--rebase`, `-r`, `--rebase=<mode>` and
# `--ff-only` do not.
merges(program) if {
	program.subcommand == "pull"
	not rebases_or_fast_forwards(program.arguments)
}

rebases_or_fast_forwards(words) if {
	some word in words
	word in {"--rebase", "-r", "--ff-only"}
}

rebases_or_fast_forwards(words) if {
	some word in words
	startswith(word, "--rebase=")
	word != "--rebase=false"
}

git(argv) := {"program": "git", "name": "git", "arguments": argv, "subcommand": argv[0], "global-options": [], "mediated": false}

call(programs) := {"call": {
	"command": concat(" && ", [p.name | some p in programs]),
	"segments": [],
	"programs": programs,
	"roots": ["/r"],
}}

test_a_merge_is_refused if {
	some _ in violation with input as call([git(["merge", "--no-edit", "FETCH_HEAD"])])
}

test_a_merging_pull_is_refused if {
	every argv in [["pull"], ["pull", "origin", "main"], ["pull", "--rebase=false"]] {
		some _ in violation with input as call([git(argv)])
	}
}

test_a_fast_forward_or_rebase_is_allowed if {
	every argv in [
		["merge", "--ff-only", "FETCH_HEAD"],
		["merge", "--abort"],
		["merge", "--continue"],
		["pull", "--rebase"],
		["pull", "-r", "origin", "x"],
		["pull", "--rebase=merges"],
		["pull", "--ff-only"],
		["rebase", "FETCH_HEAD"],
	] {
		count(violation) == 0 with input as call([git(argv)])
	}
}

# The merge usually follows a fetch on one line; every program is judged.
test_a_later_segment_is_judged_too if {
	some _ in violation with input as {"call": {
		"command": "git fetch origin x && git merge --no-edit FETCH_HEAD",
		"segments": [
			{"words": ["git", "fetch", "origin", "x"]},
			{"words": ["git", "merge", "--no-edit", "FETCH_HEAD"]},
		],
		"programs": [git(["fetch", "origin", "x"]), git(["merge", "--no-edit", "FETCH_HEAD"])],
		"roots": ["/r"],
	}}
}
