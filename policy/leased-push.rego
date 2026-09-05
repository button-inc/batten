#MUTANT-SUITE crates/batten/tests/it/forced_push.rs
#MUTANT bare-lease-unread|s@^\tword == "--force-with-lease"$@\tfalse@|a_bare_leased_push_is_refused
#MUTANT program-anchor-unread|s@^\tprogram.name == "git"$@\ttrue@|a_grammar_token_does_not_make_another_tool_gits
# A bare `--force-with-lease` trusts whatever the last fetch happened to see.
#
# MEASURED 2026-09-02, and the incident is the whole reason this exists: two
# sessions in different containers held one branch. One pushed; the other had
# already built a commit and its push was rejected non-fast-forward. Nothing in
# this engine fired at any point — git's own check was the only thing in the
# stack that noticed, after the work was written, verified and committed.
#
# THE DISTINCTION IS BARE VERSUS EXPLICIT, and `mise-tasks/land-lock.sh` already
# states it about its own CAS: "The expected value is passed EXPLICITLY
# (`<ref>:<sha>`) and must stay that way. Bare `--force-with-lease` compares
# against this clone's remote-tracking ref — what the last fetch happened to see
# — which for a ref other sessions are actively rewriting is precisely the stale
# value this must not trust. The two forms look interchangeable and are not."
#
# So the failing sequence is the ordinary one: `git fetch` moves the
# remote-tracking ref onto the sibling's commit, the bare lease then compares
# EQUAL, and the push destroys exactly what the fetch brought in. The flag chosen
# for being careful is the one that loses the work.
#
# The explicit `--force-with-lease=<ref>:<sha>` form is NOT refused, and that is
# a predicate rather than a concession: naming the sha is the assertion. You
# cannot name a value you never observed, and if the remote has moved past it git
# refuses the push itself — policy has nothing to add.
#
# WHAT THIS DOES NOT CLOSE. It cannot tell you a sibling holds the branch, only
# that you are about to overwrite whatever is there without having looked.
# Detection needs a per-branch ownership ref taken by the same server-side CAS
# `land-lock` already uses, which needs receive-pack over the vendored client
# (CLOUD-1274). Destruction closes here; detection is filed.
#
# `--force` and `-f` are the `trunk-based` preset's and are not repeated here: one
# concept, one spelling, and a second rule over one object is what the narrowing
# avoids.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document. Binding it to the tree
#   schema would type check it against a shape the engine never hands it, which is
#   CLOUD-845's defect introduced on purpose rather than caught.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.leased_push

import rego.v1

rules contains "leased-push"

violation contains {
	"rule": "leased-push",
	"verdict": "branch write unsafe",
	"subjects": [{"count": 1}],
} if {
	# ON THE PROGRAM, NOT ON THE FIRST WORD (CLOUD-1382). This read
	# `segment.words[0] == "git"`, which is the first word of the SEGMENT — the
	# remedy CLOUD-857 landed after the first word of the LINE proved silent on
	# every compound command. It is one construct short of the program, and the
	# preset this module extends measured the cost: `(git push …)`, `time …`,
	# `! …`, `{ …; }`, `command …` and `if true; then … fi` all exited 0, and
	# every one runs the push.
	#
	# `input.call.programs` is the argv the engine already read (CLOUD-1028) —
	# through environment assignments, wrappers and, since CLOUD-1382, the shell
	# grammar that can stand where a program is written. `arguments` is what THIS
	# git was handed, so the flag cannot be borrowed from another invocation on
	# the same line.
	some program in input.call.programs
	program.name == "git"
	"push" in program.arguments

	# EQUALITY, NEVER A PREFIX TEST, and this line is the whole predicate. The
	# explicit form is one word — `--force-with-lease=refs/heads/x:abc123` — so an
	# equality against the bare spelling admits it by construction. A
	# `startswith` here would refuse both and put the guard back where it was.
	some word in program.arguments
	word == "--force-with-lease"
}

# The predicate's own tests. The second is the one that matters: the distinction
# this module exists to draw is bare against explicit, so a suite that only
# proved the deny fires would not have tested the thing at all — which is the
# defect `trunk-based/no-force-push`'s own header records for its `--force`
# against `--force-with-lease` split, one spelling along.
#
# EVERY CASE PASSES `programs` AND AT LEAST ONE IS COMPOUND (CLOUD-857): a
# bare-command suite is green over exactly the hole that matters, and
# `batten policy test` refuses a mediated-call module whose cases all pass a bare
# command.
#
# AND THAT IS STILL THE LOAD-TIME TIER ONLY. These cases hand the predicate a
# resolution the ENGINE is supposed to produce, so they cannot say whether it
# does — `crates/batten/tests/it/forced_push.rs`, over the compiled binary, is
# the tier `#MUTANT-SUITE` names and the one that caught CLOUD-1382.
test_a_bare_lease_is_refused if {
	some _ in violation with input as {"call": {"programs": [{
		"program": "git",
		"name": "git",
		"arguments": ["push", "--force-with-lease", "origin", "main"],
		"mediated": false,
	}]}}
}

# THE FETCH-THEN-PUSH PAIR IS THE MEASURED SEQUENCE, not an invented one: it is
# what makes the lease compare equal.
#
# The `command` is carried beside the entries, and it is not decoration now that
# the predicate reads a RESOLUTION rather than a transcription: `programs` is
# what the boundary made of the call, and the line says what the caller typed. A
# reader can check the two against each other, which is the only thing that makes
# a hand-written entry auditable at this tier.
test_a_bare_lease_in_a_compound_command_is_refused if {
	some _ in violation with input as {"call": {
		"command": "git fetch origin && git push --force-with-lease origin main",
		"programs": [
			{"program": "git", "name": "git", "arguments": ["fetch", "origin"], "mediated": false},
			{
				"program": "git",
				"name": "git",
				"arguments": ["push", "--force-with-lease", "origin", "main"],
				"mediated": false,
			},
		],
	}}
}

# THE GRAMMAR CASE (CLOUD-1382). The caller wrote
# `time git push --force-with-lease origin main`; `time` is grammar the boundary
# steps past, so the entry names git and carries git's own argv.
test_a_grammar_token_does_not_hide_the_program if {
	some _ in violation with input as {"call": {"programs": [{
		"program": "git",
		"name": "git",
		"arguments": ["push", "--force-with-lease", "origin", "main"],
		"mediated": false,
	}]}}
}

# Reached through a path, still git — what `name` buys over `program`.
test_git_reached_through_a_path_is_still_git if {
	some _ in violation with input as {"call": {"programs": [{
		"program": "/usr/bin/git",
		"name": "git",
		"arguments": ["push", "--force-with-lease", "origin", "main"],
		"mediated": false,
	}]}}
}

test_the_explicit_expected_value_is_allowed if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"program": "git",
		"name": "git",
		"arguments": ["push", "--force-with-lease=refs/heads/main:abc123", "origin", "main"],
		"mediated": false,
	}]}}
}

test_an_ordinary_push_is_allowed if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"program": "git",
		"name": "git",
		"arguments": ["push", "-u", "origin", "work"],
		"mediated": false,
	}]}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"program": "hg",
		"name": "hg",
		"arguments": ["push", "--force-with-lease"],
		"mediated": false,
	}]}}
}

# THE FLAG MUST BE THIS PROGRAM'S. git pushes and the bare lease is on the line,
# and they are not the same invocation — the negative case an anchor that read
# the flag from anywhere would fail.
test_another_programs_lease_flag_is_not_gits if {
	count(violation) == 0 with input as {"call": {
		"command": "git push origin work; hg push --force-with-lease",
		"programs": [
			{"program": "git", "name": "git", "arguments": ["push", "origin", "work"], "mediated": false},
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

deny contains message if {
	some v in violation
	message := v.verdict
}
