#MUTANT-SUITE crates/batten/tests/it/forced_push.rs
#MUTANT bare-lease-unread|s@^\tword == "--force-with-lease"$@\tfalse@|a_bare_leased_push_is_refused
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
	# PER SEGMENT, NOT PER LINE (CLOUD-857). `input.call.segments` is
	# `hook::segments` projected — the engine's own quote-aware tokenizer — so a
	# compound command is reached. The preset this extends carries the measured
	# instance in its own header: anchored on the whole command line, it denied
	# `git push --force origin main` and ALLOWED
	# `cd /tmp && git push --force origin main`, with a green suite over it. A
	# real agent command is compound most of the time, so that silence was the
	# common case rather than an edge.
	some segment in input.call.segments
	segment.words[0] == "git"
	"push" in segment.words

	# EQUALITY, NEVER A PREFIX TEST, and this line is the whole predicate. The
	# explicit form is one word — `--force-with-lease=refs/heads/x:abc123` — so an
	# equality against the bare spelling admits it by construction. A
	# `startswith` here would refuse both and put the guard back where it was.
	some word in segment.words
	word == "--force-with-lease"
}

# The predicate's own tests. The second is the one that matters: the distinction
# this module exists to draw is bare against explicit, so a suite that only
# proved the deny fires would not have tested the thing at all — which is the
# defect `trunk-based/no-force-push`'s own header records for its `--force`
# against `--force-with-lease` split, one spelling along.
#
# EVERY CASE PASSES SEGMENTS AND AT LEAST ONE IS COMPOUND (CLOUD-857): a
# bare-command suite is green over exactly the hole that matters, and
# `batten policy test` refuses a mediated-call module whose cases all pass a bare
# command.
test_a_bare_lease_is_refused if {
	some _ in violation with input as {"call": {"segments": [{
		"words": ["git", "push", "--force-with-lease", "origin", "main"],
		"raw": "git push --force-with-lease origin main",
		"terminator": null,
	}]}}
}

test_a_bare_lease_in_a_compound_command_is_refused if {
	some _ in violation with input as {"call": {"segments": [
		{"words": ["git", "fetch", "origin"], "raw": "git fetch origin", "terminator": "&&"},
		{
			"words": ["git", "push", "--force-with-lease", "origin", "main"],
			"raw": "git push --force-with-lease origin main",
			"terminator": null,
		},
	]}}
}

test_the_explicit_expected_value_is_allowed if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["git", "push", "--force-with-lease=refs/heads/main:abc123", "origin", "main"],
		"raw": "git push --force-with-lease=refs/heads/main:abc123 origin main",
		"terminator": null,
	}]}}
}

test_an_ordinary_push_is_allowed if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["git", "push", "-u", "origin", "work"],
		"raw": "git push -u origin work",
		"terminator": null,
	}]}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["hg", "push", "--force-with-lease"],
		"raw": "hg push --force-with-lease",
		"terminator": null,
	}]}}
}

test_a_quoted_mention_is_not_an_invocation if {
	count(violation) == 0 with input as {"call": {"segments": [{
		"words": ["echo", "git push --force-with-lease origin main"],
		"raw": "echo \"git push --force-with-lease origin main\"",
		"terminator": null,
	}]}}
}

deny contains message if {
	some v in violation
	message := v.verdict
}
