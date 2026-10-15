#MUTANT-SUITE crates/batten/tests/it/forced_push.rs
#MUTANT merge-subcommand-unread|s@^\tsubcommand(arguments) == "merge"$@\tfalse@|a_merge_of_the_trunk_into_a_branch_is_refused
#MUTANT ff-only-unread|s@^\tword in {"--ff-only", "--abort", "--quit"}$@\tfalse@|a_fast_forward_merge_and_a_rebasing_pull_are_admitted
# Linear history: a branch lands as a line, so nothing weaves one. The sibling of
# `trunk-based`, and its own bundle so each enabling row names one class.
#
# A trunk that refuses merge commits refuses them at the FAST-FORWARD, after the
# matrix has been bought. The commit that will be refused is made much earlier,
# by one of two calls: `git merge <ref>`, or `git pull` without `--rebase`, which
# is a fetch followed by that same merge. This refuses both at the call, where
# the remedy is one command rather than a history to unpick (CLOUD-2273).
#
# What stays admitted, and why each is linear:
#
# * `git merge --ff-only` moves a ref along history that is already a line, and
#   refuses rather than writing a merge commit when it cannot.
# * `git merge --abort` and `--quit` end a merge in progress; they write nothing.
# * `git pull --rebase` (`-r`, `--rebase=<mode>`) replays the local commits onto
#   what it fetched, and `git pull --ff-only` refuses rather than merging.
#
# `pull.rebase = true` in git's own config makes a bare `git pull` rebase too,
# and the call cannot see it: `input.call` is the argv, not the clone's config.
# So a bare pull is refused whatever the config says, and the route names the
# spelling that does not depend on it. Refusing a call that would have rebased
# costs one flag; admitting one that would have merged costs the landing.
#
# Names no repository, no ref and no task: this is true of the practice, which is
# what a vendored preset may contain (non-negotiable rule 1).
package batten.linear_history

import rego.v1

rules contains "commit write loose"

violation contains {
	"rule": "commit write loose",
	"verdict": "commit write loose",
} if {
	# ON THE PROGRAM, for `no-force-push.rego`'s reason (CLOUD-1382): the argv the
	# engine resolved, through wrappers and shell grammar, never a word of the line.
	some program in input.call.programs
	program.name == "git"
	weaves(program.arguments)
}

# THE SUBCOMMAND, not membership. `"merge" in arguments` would fire on
# `git commit -m merge` and `git log --grep merge`; the subcommand is the first
# argument that is not a global option, and `-C <path>` / `-c <k=v>` take a value,
# so the word after them is skipped too. The `git` preset reads it the same way.
subcommand(arguments) := word if {
	positions := [i | some i, word in arguments; not startswith(word, "-"); not value_of_global(arguments, i)]
	count(positions) > 0
	word := arguments[positions[0]]
}

value_of_global(arguments, i) if {
	i > 0
	arguments[i - 1] in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
}

weaves(arguments) if {
	subcommand(arguments) == "merge"
	not linear_merge(arguments)
}

weaves(arguments) if {
	subcommand(arguments) == "pull"
	not linear_pull(arguments)
}

linear_merge(arguments) if {
	some word in arguments
	word in {"--ff-only", "--abort", "--quit"}
}

linear_pull(arguments) if {
	some word in arguments
	word in {"--rebase", "-r", "--ff-only"}
}

# `--rebase=<mode>` rebases for every mode but `false`, which is an explicit
# request for the merge this refuses.
linear_pull(arguments) if {
	some word in arguments
	startswith(word, "--rebase=")
	word != "--rebase=false"
}

# The predicate's own tests, `with input as` for `no-force-push.rego`'s reason.
# The compiled-binary tier is `crates/batten/tests/it/forced_push.rs`, judged
# against the committed table.
test_a_merge_of_the_trunk_is_caught if {
	some v in violation with input as {"call": {
		"command": "git merge origin/main",
		"programs": [{"program": "git", "name": "git", "arguments": ["merge", "origin/main"], "mediated": false}],
	}}
	v.rule == "commit write loose"
}

test_a_bare_pull_is_caught if {
	some v in violation with input as {"call": {
		"command": "git pull origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["pull", "origin", "main"], "mediated": false}],
	}}
	v.rule == "commit write loose"
}

# A merge later in a list is reached, one entry per program (CLOUD-857's shape).
test_a_merge_later_in_a_list_is_caught if {
	some v in violation with input as {"call": {
		"command": "git fetch origin && git merge origin/main",
		"programs": [{"program": "git", "name": "git", "arguments": ["fetch", "origin"], "mediated": false}, {"program": "git", "name": "git", "arguments": ["merge", "origin/main"], "mediated": false}],
	}}
	v.rule == "commit write loose"
}

test_a_global_option_does_not_hide_the_subcommand if {
	some v in violation with input as {"call": {
		"command": "git -C /work merge origin/main",
		"programs": [{"program": "git", "name": "git", "arguments": ["-C", "/work", "merge", "origin/main"], "mediated": false}],
	}}
	v.rule == "commit write loose"
}

test_a_pull_asking_for_the_merge_is_caught if {
	some v in violation with input as {"call": {
		"command": "git pull --rebase=false origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["pull", "--rebase=false", "origin", "main"], "mediated": false}],
	}}
	v.rule == "commit write loose"
}

test_a_fast_forward_merge_is_left_alone if {
	count(violation) == 0 with input as {"call": {
		"command": "git merge --ff-only origin/main",
		"programs": [{"program": "git", "name": "git", "arguments": ["merge", "--ff-only", "origin/main"], "mediated": false}],
	}}
}

test_an_abort_is_left_alone if {
	count(violation) == 0 with input as {"call": {
		"command": "git merge --abort",
		"programs": [{"program": "git", "name": "git", "arguments": ["merge", "--abort"], "mediated": false}],
	}}
}

test_a_rebasing_pull_is_left_alone if {
	count(violation) == 0 with input as {"call": {
		"command": "git pull --rebase origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["pull", "--rebase", "origin", "main"], "mediated": false}],
	}}
	count(violation) == 0 with input as {"call": {
		"command": "git pull --rebase=interactive",
		"programs": [{"program": "git", "name": "git", "arguments": ["pull", "--rebase=interactive"], "mediated": false}],
	}}
}

# A WORD IS NOT A SUBCOMMAND: `merge` as a message or a search term is an
# argument to something else.
test_the_word_elsewhere_is_not_a_merge if {
	count(violation) == 0 with input as {"call": {
		"command": "git commit -m merge",
		"programs": [{"program": "git", "name": "git", "arguments": ["commit", "-m", "merge"], "mediated": false}],
	}}
	count(violation) == 0 with input as {"call": {
		"command": "git merge-base HEAD origin/main",
		"programs": [{"program": "git", "name": "git", "arguments": ["merge-base", "HEAD", "origin/main"], "mediated": false}],
	}}
}

test_another_tools_merge_is_not_judged if {
	count(violation) == 0 with input as {"call": {
		"command": "hg merge",
		"programs": [{"program": "hg", "name": "hg", "arguments": ["merge"], "mediated": false}],
	}}
}
