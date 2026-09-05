#MUTANT-SUITE crates/batten/tests/it/preset_segments.rs
#MUTANT force-flag-unread|s@^\tword in {"--force", "-f"}$@\tfalse@|a_force_push_alone_still_denies
#MUTANT program-anchor-unread|s@^\tprogram.name == "git"$@\ttrue@|another_tool_is_not_judged_wherever_it_sits
# Trunk-based development: a shared branch is not rewritten under its readers.
#
# `--force-with-lease` is deliberately NOT matched. It is the sanctioned form —
# it refuses when the remote moved, which is the whole difference between
# "I know what I am replacing" and "replace whatever is there". A preset that
# banned both would push its consumers toward the bypass rather than toward the
# safer flag.
#
# Names no repository, no ref and no task: this is true of the practice, which is
# what a vendored preset may contain (non-negotiable rule 1).
package batten.trunk_based

import rego.v1

rules contains "no-force-push"

violation contains {
	"rule": "no-force-push",
	"verdict": "trunk push forced",
} if {
	# ON THE PROGRAM, NOT ON THE FIRST WORD (CLOUD-1382). This is the anchor's
	# third home and the second correction, so both are worth carrying.
	#
	# It began as `split(input.call.command, " ")[0] == "git"` — the first word
	# of the whole LINE — and CLOUD-857 measured what that cost: the bare
	# `git push --force origin main` denied while
	# `cd /tmp && git push --force origin main` was allowed.
	#
	# CLOUD-857's remedy was `segment.words[0] == "git"`, and that was still not
	# the program. Measured 2026-09-03, adjudication only: `(git push --force
	# origin main)`, `time …`, `! …`, `{ …; }`, `command …` and
	# `if true; then … fi` ALL exited 0, and every one of them runs the force
	# push. Six bypasses, one keystroke each, because `words[0]` is the first
	# WORD where the predicate means the first PROGRAM.
	#
	# `input.call.programs` is the argv the engine already read (CLOUD-1028) —
	# through environment assignments, wrapper programs and, since CLOUD-1382,
	# the shell grammar that may stand where a program is written. `arguments`
	# is what THIS program was handed, so the flag is correlated with git's own
	# argv rather than with anything else that happened to share the line.
	#
	# There is no `split` here and there must not be one: a second tokenizer in
	# Rego is a second authority over one call, which is what CLOUD-857 measured
	# and what CLOUD-843's wave would arrive with ~80 times over.
	#
	# THE ENGINE HALF IS A DECLARED STOPGAP AND THIS ROW STAYS OPEN. A list of
	# grammar tokens cannot enumerate a grammar; `hook.rs`'s `SHELL_GRAMMAR`
	# says so at its own site, and the parsed command line is CLOUD-1381.
	some program in input.call.programs
	program.name == "git"
	"push" in program.arguments
	some word in program.arguments
	word in {"--force", "-f"}
}

# The predicate's own tests (CLOUD-835), and the second is the point: the
# distinction this preset exists to draw is `--force` against
# `--force-with-lease`, so a suite that only proved the deny fires would not
# have tested the practice at all.
#
# `with input as` rather than a declared fixture: the input is local to the test
# that depends on it, which is OPA and Conftest's own shape, and a preset ships
# with no consumer tree to declare documents from.
#
# THESE LIVE IN THE REGISTERED MODULE, AND THAT COST WAS MEASURED. `policy::load`
# compiles and smoke-queries every registered module on every mediated call, so a
# `test_` rule here is evaluated on the hook path — the one place this repository
# budgets in milliseconds. Measured 2026-08-21, `perf-pair` against the merge
# base on one machine: `hook` 3.2 ms -> 3.3 ms and `wired` 7.2 ms -> 7.4 ms, both
# ratio 1.03, inside the 0.966-1.102 spread a null comparison of one identical
# binary produces. `noop`, `passthrough` and `check` did not move.
#
# So a sibling-file convention that kept tests out of the loaded set buys
# nothing, and is not worth the second load path it would cost. Re-measure before
# concluding otherwise: to move this row, bring a number.
#
# AND EVERY CASE HERE IS STILL HAND-WRITTEN `programs`, WHICH IS WHY THE TIER
# ABOVE IS NAMED IN `#MUTANT-SUITE`. A `with input as` case supplies the very
# resolution that was wrong — it cannot tell whether the ENGINE resolves `(git`
# to `git`, only that the predicate would decide correctly if it did.
# `crates/batten/tests/it/preset_segments.rs` drives the compiled binary, and
# that is the tier that caught all six of CLOUD-1382's bypasses.
test_no_force_push if {
	some v in violation with input as {"call": {
		"command": "git push --force origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "--force", "origin", "main"], "mediated": false}],
	}}
	v.rule == "no-force-push"
}

test_short_force_flag_is_caught_too if {
	some v in violation with input as {"call": {
		"command": "git push -f origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "-f", "origin", "main"], "mediated": false}],
	}}
	v.rule == "no-force-push"
}

# THE CASE CLOUD-857 WAS FILED ON: the force push is the SECOND element of a
# list, so the first word of the line is `cd`. One entry per segment, so the
# element carrying git is reached whatever precedes it.
#
# THE `command` IS CARRIED ON EVERY CASE HERE, and it is not decoration now that
# the predicate reads a RESOLUTION rather than a transcription: `programs` says
# what the boundary made of the call, and the line beside it says what the caller
# actually typed. A reader can check the two against each other, which is the
# only thing that makes a hand-written entry auditable at this tier.
test_a_force_push_later_in_a_list_is_caught if {
	some v in violation with input as {"call": {
		"command": "cd /tmp && git push --force origin main",
		"programs": [{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false}, {"program": "git", "name": "git", "arguments": ["push", "--force", "origin", "main"], "mediated": false}],
	}}
	v.rule == "no-force-push"
}

# THE CASE CLOUD-1382 WAS FILED ON. `time` is grammar the boundary steps past, so
# the entry names `git` and carries git's own argv — where `words[0]` was `time`
# and the predicate saw no git at all.
test_a_grammar_token_does_not_hide_the_program if {
	some v in violation with input as {"call": {
		"command": "time git push --force origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "--force", "origin", "main"], "mediated": false}],
	}}
	v.rule == "no-force-push"
}

# A PROGRAM REACHED THROUGH A PATH IS THE SAME PROGRAM, which is what `name`
# buys over `program` and what a token comparison would answer no for.
test_git_reached_through_a_path_is_still_git if {
	some v in violation with input as {"call": {
		"command": "/usr/bin/git push --force origin main",
		"programs": [{"program": "/usr/bin/git", "name": "git", "arguments": ["push", "--force", "origin", "main"], "mediated": false}],
	}}
	v.rule == "no-force-push"
}

test_force_with_lease_is_left_alone if {
	count(violation) == 0 with input as {"call": {
		"command": "git push --force-with-lease origin main",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "--force-with-lease", "origin", "main"], "mediated": false}],
	}}
}

# The distinction survives a compound command, which is the half a deny-only
# suite would not have tested: the same shape, the sanctioned flag.
test_force_with_lease_survives_a_list_too if {
	count(violation) == 0 with input as {"call": {
		"command": "cd /tmp && git push --force-with-lease origin main",
		"programs": [{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false}, {"program": "git", "name": "git", "arguments": ["push", "--force-with-lease", "origin", "main"], "mediated": false}],
	}}
}

# A MENTION IS NOT AN INVOCATION (CLOUD-269). The quoted span survives as ONE
# word, so the program is `echo` and git never appears as one.
test_a_quoted_mention_does_not_fire if {
	count(violation) == 0 with input as {"call": {
		"command": "echo \"git push --force origin main\"",
		"programs": [{"program": "echo", "name": "echo", "arguments": ["git push --force origin main"], "mediated": false}],
	}}
}

# AND THE FLAG MUST BE THIS PROGRAM'S. Anchoring on the program while reading the
# flag from anywhere on the line is the defect one level up, so the negative case
# is written: git is invoked, `--force` is on the line, and they are not the same
# invocation.
test_another_programs_force_flag_is_not_gits if {
	count(violation) == 0 with input as {"call": {
		"command": "git push origin feature; hg push --force",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "origin", "feature"], "mediated": false}, {"program": "hg", "name": "hg", "arguments": ["push", "--force"], "mediated": false}],
	}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {
		"command": "hg push --force",
		"programs": [{"program": "hg", "name": "hg", "arguments": ["push", "--force"], "mediated": false}],
	}}
}
