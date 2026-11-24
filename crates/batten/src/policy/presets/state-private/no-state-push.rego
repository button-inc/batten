#MUTANT-SUITE crates/batten/tests/it/state_push.rs
#MUTANT state-bytes-unread|s@^\tcount(carried) > 0$@\tfalse@|a_state_journal_copied_into_the_project_tree_is_refused_at_push
#MUTANT state-repo-exemption-unread|s@^\tnot exempt$@\ttrue@|the_same_file_pushed_to_the_state_repo_is_allowed
#MUTANT empty-blob-counted|s@^\tentry.size > 0$@\ttrue@|an_empty_file_is_never_state_bytes
# A push never carries session state to a remote other than the state repo
# (CLOUD-2887).
#
# Measured 2026-11-24: a dispatched session copied its mutant verdict journal
# into the project tree as `verdicts/28-of-32.tsv` and pushed it to the public
# repository. Session state is private, and its one destination is the state
# repo `BATTEN_STATE_REPO` names.
#
# THE RECORD IS THE ENGINE'S. `input.facts["state-push"]` lists each blob the
# push would carry whose bytes equal a private store's file (`equal`) or begin an
# append-only one (`prefix`), on EVERY remote and at every size. The two rules
# that decide are here, so each has a mutant a case kills: the state repo is
# exempt, and an empty blob is no record. `null` means no push, or one that
# could not be looked at, and nothing here refuses on it.
#
# BYTES, NEVER A PATH: a rename does not evade it, and a project file that
# happens to share a store's name is not refused.
#
# Names no repository and no store path: this is true of the practice, which is
# what a vendored preset may contain (non-negotiable rule 1).
package batten.state_private

import rego.v1

rules contains "path carry loose"

violation contains {
	"rule": "path carry loose",
	"verdict": "path carry loose",
	"subjects": subjects,
} if {
	# ON THE PROGRAM, for `no-force-push.rego`'s reason (CLOUD-1382): the argv
	# the engine resolved, through wrappers and shell grammar.
	some program in input.call.programs
	program.name == "git"
	program.subcommand == "push"
	not exempt
	count(carried) > 0
	subjects := [{"artifact": sprintf("%s %s %s", [entry.path, entry.store, entry.arm])} |
		some entry in carried
	]
}

# The fact's list, or none: `some .. in` over a `null` faults the interpreter
# (#1276), so absent and `null` alike are the empty list. Two exclusive
# definitions rather than an `else`, which keeps the preset on bytecode.
listed := list if {
	list = input.facts["state-push"].carried
	is_array(list)
}

listed := [] if not is_array(input.facts["state-push"].carried)

# The one allowed destination: the push's remote IS the named state repo. An
# unset variable names none, so nothing is exempt.
exempt if {
	fact := input.facts["state-push"]
	is_string(fact.state_repo)
	fact.remote == fact.state_repo
}

# Each carried blob that holds a record: an empty file is no one's bytes.
carried contains entry if {
	some entry in listed
	entry.size > 0
}

# The predicate's own tests, `with input as`. The compiled-binary tier is
# `crates/batten/tests/it/state_push.rs`.
push_call := {
	"command": "git push origin HEAD",
	"programs": [{"program": "git", "name": "git", "arguments": ["push", "origin", "HEAD"], "subcommand": "push", "global-options": [], "mediated": false}],
}

journal := {"path": "verdicts/28-of-32.tsv", "store": "mutate-verdicts", "arm": "equal", "size": 245012}

test_a_journal_pushed_to_the_project_is_refused if {
	some v in violation with input as {
		"call": push_call,
		"facts": {"state-push": {"remote": "example/project", "state_repo": "example/state", "carried": [journal]}},
	}
	v.rule == "path carry loose"
	v.subjects == [{"artifact": "verdicts/28-of-32.tsv mutate-verdicts equal"}]
}

test_the_state_repo_is_exempt if {
	count(violation) == 0 with input as {
		"call": push_call,
		"facts": {"state-push": {"remote": "example/state", "state_repo": "example/state", "carried": [journal]}},
	}
}

# AN UNSET STATE REPO NAMES NO DESTINATION: a `null` remote equal to a `null`
# state repo exempts nothing.
test_no_state_repo_exempts_nothing if {
	some v in violation with input as {
		"call": push_call,
		"facts": {"state-push": {"remote": null, "state_repo": null, "carried": [journal]}},
	}
	v.rule == "path carry loose"
}

test_an_empty_blob_is_left_alone if {
	count(violation) == 0 with input as {
		"call": push_call,
		"facts": {"state-push": {"remote": "example/project", "state_repo": "example/state", "carried": [{"path": "verdicts/.gitkeep", "store": "journal", "arm": "equal", "size": 0}]}},
	}
}

test_nothing_carried_is_left_alone if {
	count(violation) == 0 with input as {
		"call": push_call,
		"facts": {"state-push": {"remote": "example/project", "state_repo": "example/state", "carried": []}},
	}
}

test_a_null_fact_is_left_alone if {
	count(violation) == 0 with input as {"call": push_call, "facts": {"state-push": null}}
}

# A WORD IS NOT A SUBCOMMAND: `push` as a commit message.
test_another_subcommand_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {
			"command": "git commit -m push",
			"programs": [{"program": "git", "name": "git", "arguments": ["commit", "-m", "push"], "subcommand": "commit", "global-options": [], "mediated": false}],
		},
		"facts": {"state-push": {"remote": "example/project", "state_repo": "example/state", "carried": [journal]}},
	}
}
