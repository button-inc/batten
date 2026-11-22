#MUTANT-SUITE crates/batten/tests/it/forced_push.rs
#MUTANT bare-lease-unread|s@^\tunasserted(word)$@\tfalse@|a_bare_leased_push_is_refused_by_the_preset
#MUTANT program-anchor-unread|s@^\tprogram.name == "git"$@\ttrue@|a_lease_with_force_if_includes_is_allowed
#MUTANT includes-unread|s@^\tnot "--force-if-includes" in program.arguments$@\ttrue@|a_lease_with_force_if_includes_is_allowed
# Trunk-based development: a leased push that names no expected value is a force.
#
# git's own manual says so (git-push(1), `--force-with-lease`): supplying the
# option "without an expected value, i.e. as `--force-with-lease` or
# `--force-with-lease=<refname>` interacts very badly with anything that
# implicitly runs `git fetch` on the remote to be pushed to in the background",
# and its protection over `--force` "is trivially defeated if some background
# process is updating refs". The lease compares against this clone's
# remote-tracking ref, so `git fetch` followed by the push compares EQUAL and
# overwrites exactly what the fetch brought in. Measured here 2026-09-02: two
# sessions held one branch, and git's non-fast-forward check was the only thing
# that noticed, after the work was written.
#
# So the practice is BARE OR REF-ONLY VERSUS ASSERTED:
#   - `--force-with-lease=<ref>:<sha>` names the commit expected. You cannot name
#     a value you never observed, and git refuses the push if the remote moved.
#   - `--force-with-lease` with `--force-if-includes` is git's own remedy for the
#     background-fetch case: the push is refused unless the remote-tracking tip is
#     reachable from the local branch's reflog, i.e. was integrated, not merely
#     fetched.
# Both are allowed. `--force` and `-f` are `no-force-push`'s, not repeated here:
# one concept, one module.
#
# Names no repository, no ref and no task (non-negotiable rule 1). This was a
# repository-local module (`policy/leased-push.rego`) while the `trunk-based`
# preset's header called the bare lease "the sanctioned form", so every consumer
# enabling `trunk-based` was told the unsafe spelling was the safe one (plan item
# 4c). Its own preset, not a second `trunk-based` module, so an existing row named
# `trunk push forced` keeps naming the one class it raises (CLOUD-2273).
package batten.lease_asserted

import rego.v1

rules contains "branch write unnamed"

violation contains {
	"rule": "branch write unnamed",
	"verdict": "branch write unnamed",
	"subjects": [{"count": 1}],
} if {
	# ON THE PROGRAM AND ITS SUBCOMMAND (CLOUD-1382, CLOUD-2691): the argv the
	# engine resolved through wrappers and shell grammar, and `push` as git's
	# subcommand rather than any word, so `git stash push` is not a push.
	some program in input.call.programs
	program.name == "git"
	program.subcommand == "push"
	some word in program.arguments
	unasserted(word)
	not "--force-if-includes" in program.arguments
}

# The bare flag.
unasserted(word) if word == "--force-with-lease"

# `=<ref>` with no `:<expect>`: protects that ref by the same tracking-ref
# comparison as the bare flag, so it is the same hazard.
unasserted(word) if {
	startswith(word, "--force-with-lease=")
	not contains(word, ":")
}

push(arguments) := {"call": {"programs": [{
	"program": "git",
	"name": "git",
	"arguments": array.concat(["push"], arguments),
	"subcommand": "push",
	"global-options": [],
	"mediated": false,
}]}}

test_a_bare_lease_is_refused if {
	some _ in violation with input as push(["--force-with-lease", "origin", "main"])
}

test_a_ref_only_lease_is_refused if {
	some _ in violation with input as push(["--force-with-lease=main", "origin", "main"])
}

# THE FETCH-THEN-PUSH PAIR IS THE MEASURED SEQUENCE: it is what makes the lease
# compare equal. Compound, so the predicate is shown reading the resolved program.
test_a_bare_lease_in_a_compound_command_is_refused if {
	some _ in violation with input as {"call": {
		"command": "git fetch origin && git push --force-with-lease origin main",
		"programs": [
			{"program": "git", "name": "git", "arguments": ["fetch", "origin"], "subcommand": "fetch", "mediated": false},
			{
				"program": "git",
				"name": "git",
				"arguments": ["push", "--force-with-lease", "origin", "main"],
				"subcommand": "push",
				"mediated": false,
			},
		],
	}}
}

test_git_reached_through_a_path_is_still_git if {
	some _ in violation with input as {"call": {"programs": [{
		"program": "/usr/bin/git",
		"name": "git",
		"arguments": ["push", "--force-with-lease", "origin", "main"],
		"subcommand": "push",
		"mediated": false,
	}]}}
}

test_the_explicit_expected_value_is_allowed if {
	count(violation) == 0 with input as push(["--force-with-lease=refs/heads/main:abc123", "origin", "main"])
}

test_a_lease_with_force_if_includes_is_allowed if {
	count(violation) == 0 with input as push(["--force-with-lease", "--force-if-includes", "origin", "main"])
}

test_an_ordinary_push_is_allowed if {
	count(violation) == 0 with input as push(["-u", "origin", "work"])
}

test_a_stash_push_is_not_a_push if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"program": "git",
		"name": "git",
		"arguments": ["stash", "push", "--force-with-lease"],
		"subcommand": "stash",
		"mediated": false,
	}]}}
}

# THE FLAG MUST BE THIS PROGRAM'S: git pushes and a bare lease is on the line,
# but in another program's argv.
test_another_programs_lease_flag_is_not_gits if {
	count(violation) == 0 with input as {"call": {
		"command": "git push origin work; hg push --force-with-lease",
		"programs": [
			{"program": "git", "name": "git", "arguments": ["push", "origin", "work"], "subcommand": "push", "mediated": false},
			{"program": "hg", "name": "hg", "arguments": ["push", "--force-with-lease"], "mediated": false},
		],
	}}
}

test_a_quoted_mention_is_not_an_invocation if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"program": "echo",
		"name": "echo",
		"arguments": ["git push --force-with-lease origin main"],
		"mediated": false,
	}]}}
}
