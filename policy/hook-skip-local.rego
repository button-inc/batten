#MUTANT-SUITE crates/batten/tests/it/hook_skip_local.rs
#MUTANT skip-assignment-unread|s@^\tsome word in segment.words$@\tsome word in []@|a_local_step_skip_is_refused
#MUTANT ci-carve-unread|s@^\tnot ci_lane$@\tfalse@|the_declared_ci_carve_is_not_judged_here
# Switching a gate off for a local commit is a decision, not a flag (CLOUD-1340).
#
# MEASURED ON THE BRANCH THAT FILED IT, and the incident is the whole reason this
# exists rather than an argument for it. `hooks-wiring-check` refused; the session
# read the refusal as environmental and unfixable, set `HK_SKIP_STEPS` on three
# commits, wrote that false justification into two commit messages, and put a
# four-option menu to a human. `batten wiring reclaim -y` cleared the condition in
# one command. Nothing in this engine fired at any point: the variable is read by
# `hk`, which batten never sees, so the gate that was switched off had no way to
# say so.
#
# THE ASYMMETRY IS THE FINDING. `ci-suite-lane` already governs `HK_SKIP_STEPS`
# where CI sets it -- `input.tree.documents` over the workflow files, refusing the
# `test:bats` carve coming apart -- so the DECLARED use is gated and the ad-hoc
# one was not. A variable a repository deliberately depends on in one place and
# refuses nowhere else is a hole shaped exactly like its own legitimate use, which
# is why this reads the mediated call rather than widening that row.
#
# WHY THIS IS A MODULE RATHER THAN A `shape` ROW. `refusal.rs` is explicit that a
# refusal composed from a consumer `[[rule]]` row carries no declared class and no
# token an admission could bind, so such a row could only ever be reached through
# `bypass_env` -- the password shape CLOUD-1051 retired on the ground that *the
# point of the admission mechanism is that the bare variable stops working*. A
# module raises a declared class, which is what makes the refusal one a reader can
# look up.
#
# AND THE CLASS DECLARES NO OVERRIDE, which is a decision rather than an omission
# and was reversed once while landing. The route drafted here read "the step
# cannot be satisfied at this commit -- it reads a generated file a LATER commit in
# the same sequence writes"; that case is REAL and was met three times on this
# branch, over `bench/suites/RESULTS.md` during a rebase. It is already served,
# though, by `--no-verify` plus the articulation block `commit check` requires
# (CLOUD-1278) -- gated, and leaving a record in the commit where a reviewer reads
# it. `shell edit refused` is the precedent for a class that refuses outright.
#
# So `--no-verify` is the route and this class has none, which also drops a
# `verdict-override-added` weakening the branch would otherwise have had to
# declare. That is the better trade in both directions: one object gets one
# authority, and the more visible mechanism is the one that survives.
#
# WHAT THIS DOES NOT CLOSE, for the same reason stated forwards: `--no-verify` is
# NOT judged here. `commit check` already refuses a commit that wrote a protected
# path with no block claiming it, and it caught this same session's `--no-verify`
# amend by noticing the block had been dropped. This closes the variable, which
# nothing read.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document. `ci-suite-lane` is the
#   tree-surface half over the same variable and they do not overlap -- one reads
#   a workflow file, this reads a command.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.hook_skip_local

import rego.v1

rules contains "hook-skip-local"

# The declared carve, which is CI's and is judged by `ci-suite-lane` instead.
#
# NARROW ON PURPOSE AND ANCHORED AT BOTH ENDS. This exempts the one spelling the
# `ci` job actually hands hk, and nothing that merely contains it -- so
# `HK_SKIP_STEPS=test:bats,batten-check` is still refused, which is the shape an
# author reaches for when adding "just one more" to a line they found in a
# workflow. A prefix test here would hand back the whole hole.
ci_lane if {
	some segment in input.call.segments
	some word in segment.words
	word == "HK_SKIP_STEPS=test:bats"
}

violation contains {
	"rule": "hook-skip-local",
	"verdict": "hook skip unseen",
	"subjects": [{"count": 1}],
} if {
	# PER SEGMENT, NOT PER LINE (CLOUD-857). A real agent command is compound most
	# of the time, and the preset this sits beside carries the measured instance:
	# anchored on the whole command line, `git push --force` denied while
	# `cd /tmp && git push --force` was allowed, with a green suite over it.
	some segment in input.call.segments

	# THE ASSIGNMENT IS A WORD, WHICH IS WHY THIS READS `words` AND NOT
	# `programs`. `hook::is_env_assignment` is what the boundary uses to look
	# THROUGH an assignment when resolving the effective program, so `programs`
	# reports `git` for `HK_SKIP_STEPS=x git commit` and never the variable. The
	# tokens survive in `words` exactly as written, which is the surface that can
	# see this at all.
	some word in segment.words
	regex.match(data.batten.patterns["hook-step-skip-assignment"], word)

	not ci_lane
}

# The predicate's own tests. The exemption case is the one that matters: a module
# that only proved the deny fires would be satisfied by a build that refuses the
# `ci` job's own line, which is the shape that gets a guard switched off rather
# than satisfied.
#
# EVERY CASE PASSES SEGMENTS AND AT LEAST ONE IS COMPOUND (CLOUD-857):
# `batten policy test` refuses a mediated-call module whose cases all pass a bare
# command.
test_a_local_step_skip_is_refused if {
	some _ in violation with input as {"call": {"segments": [{
		"words": ["HK_SKIP_STEPS=hooks-wiring-check", "git", "commit", "-m", "x"],
		"raw": "HK_SKIP_STEPS=hooks-wiring-check git commit -m x",
		"terminator": null,
	}]}}
}

test_a_step_skip_in_a_compound_command_is_refused if {
	some _ in violation with input as {"call": {"segments": [
		{"words": ["git", "add", "-A"], "raw": "git add -A", "terminator": "&&"},
		{
			"words": ["HK_SKIP_STEPS=batten-check", "git", "commit", "-m", "x"],
			"raw": "HK_SKIP_STEPS=batten-check git commit -m x",
			"terminator": null,
		},
	]}}
}

# THE EXEMPTION, AND IT IS EXACT. `ci.yml` hands hk this precise value; anything
# else is an author's own decision and is judged.
test_the_declared_ci_carve_is_not_judged_here if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["HK_SKIP_STEPS=test:bats", "mise", "run", "ci"],
		"raw": "HK_SKIP_STEPS=test:bats mise run ci",
		"terminator": null,
	}]}}
}

# A VALUE THAT MERELY CONTAINS THE CARVE IS STILL A DECISION. This is the arm a
# prefix test would lose, and it is the one an author actually reaches for.
test_the_carve_with_a_step_appended_is_refused if {
	some _ in violation with input as {"call": {"segments": [{
		"words": ["HK_SKIP_STEPS=test:bats,batten-check", "mise", "run", "ci"],
		"raw": "HK_SKIP_STEPS=test:bats,batten-check mise run ci",
		"terminator": null,
	}]}}
}

test_an_ordinary_commit_is_allowed if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["git", "commit", "-m", "x"],
		"raw": "git commit -m x",
		"terminator": null,
	}]}}
}

# ANOTHER VARIABLE IS NOT THIS ONE. The pattern is anchored at its left edge, so a
# name that merely ends in the same letters does not reach it.
test_another_assignment_is_not_judged if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["RUST_LOG=debug", "git", "commit", "-m", "x"],
		"raw": "RUST_LOG=debug git commit -m x",
		"terminator": null,
	}]}}
}

test_a_quoted_mention_is_not_an_invocation if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["echo", "set HK_SKIP_STEPS=x to skip a step"],
		"raw": "echo \"set HK_SKIP_STEPS=x to skip a step\"",
		"terminator": null,
	}]}}
}

deny contains message if {
	some v in violation
	message := v.verdict
}
