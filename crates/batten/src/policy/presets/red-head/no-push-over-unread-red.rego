#MUTANT-SUITE crates/batten/tests/it/head_push_unread.rs
#MUTANT push-subcommand-unread|s@^\tsubcommand(program.arguments) == "push"$@\tfalse@|a_push_over_an_unread_red_check_is_refused
#MUTANT read-receipt-ignored|s@^\tentry.read == false$@\ttrue@|reading_the_failed_check_admits_the_push
# A push over a red head owes each failed check's log a read (CLOUD-2270).
#
# When a landing's wait stops red, the failed checks' logs say why, and a push
# replacing that head starts a new run that buries them. The incident this
# closes: the stop named one failure while another job still ran, the agent read
# the one it was shown, pushed, and the other's failure was never seen.
#
# THE RECORD IS THE ENGINE'S. `land` writes `red-head.<branch>` when a wait stops
# red and removes it when one answers green; `input.facts["red-head"]` projects
# it with `read` per failed run, a stat of either receipt below that a read
# mints. `null` means no red head, and nothing here refuses on it.
#
# ENABLING IT TAKES TWO `[[mint]]` ROWS BESIDE ITS `[[rule]]`, because a preset
# ships no mint and `read` is only ever true where one wrote the receipt:
#
#   [[mint]]  name = "check-log-read"  tool = "get_job_logs"   key = "named"
#             key_from = "job_id"  requires = ["job_id", "logs_content"]
#   [[mint]]  name = "check-run-read"  tool = "get_check_run"  key = "named"
#             key_from = "id"      requires = ["id", "conclusion"]
#
# The second is the read for a failed check no Actions job runs (a third-party
# app's): it has a check run and no job log, and without it that failure could
# never be paid. Either receipt pays a run; two rows may not share one name.
# Each needs `mode = "replace"` and a `body` such as `"{now}"`.
#
# A RUNNING CHECK ALONE NEVER REFUSES: it has no log to read yet, and a refusal
# with no remedy would hold the branch hostage to a runner. It is NAMED when a
# failure refuses, because the push abandons its verdict too.
#
# Names no repository, no check and no server: this is true of the practice,
# which is what a vendored preset may contain (non-negotiable rule 1).
package batten.red_head

import rego.v1

rules contains "job read unread"

violation contains {
	"rule": "job read unread",
	"verdict": "job read unread",
	"subjects": subjects,
} if {
	# ON THE PROGRAM, for `no-force-push.rego`'s reason (CLOUD-1382): the argv
	# the engine resolved, through wrappers and shell grammar.
	some program in input.call.programs
	program.name == "git"
	pushes(program)
	count(unread) > 0
	subjects := array.concat(
		[{"artifact": sprintf("%s job %s", [entry.name, entry.id])} | some entry in unread],
		[{"artifact": sprintf("%s still running", [name])} | some name in input.facts["red-head"].running],
	)
}

pushes(program) if {
	subcommand(program.arguments) == "push"
}

# Each failed check whose log no receipt says was read, in record order.
unread := [entry |
	some entry in input.facts["red-head"].failed
	entry.read == false
]

# THE SUBCOMMAND, not membership, copied from `linear-history`'s
# `no-merge-into-branch.rego`: the first argument that is not a global option,
# skipping the value a `-C <path>` or `-c <k=v>` takes.
subcommand(arguments) := word if {
	positions := [i | some i, word in arguments; not startswith(word, "-"); not value_of_global(arguments, i)]
	count(positions) > 0
	word := arguments[positions[0]]
}

value_of_global(arguments, i) if {
	i > 0
	arguments[i - 1] in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
}

# The predicate's own tests, `with input as`. The compiled-binary tier is
# `crates/batten/tests/it/head_push_unread.rs`.
red := {
	"head": "abc123",
	"failed": [{"id": "101", "name": "windows", "read": false}],
	"running": ["macos"],
}

test_a_push_over_an_unread_failure_is_caught if {
	some v in violation with input as {
		"call": {
			"command": "git push origin HEAD",
			"programs": [{"program": "git", "name": "git", "arguments": ["push", "origin", "HEAD"], "mediated": false}],
		},
		"facts": {"red-head": red},
	}
	v.rule == "job read unread"
	{"artifact": "windows job 101"} in v.subjects
	{"artifact": "macos still running"} in v.subjects
}

# A push later in a compound command is reached, one entry per program.
test_a_compound_push_is_caught if {
	some v in violation with input as {
		"call": {
			"command": "cd x && git push origin HEAD",
			"programs": [
				{"program": "cd", "name": "cd", "arguments": ["x"], "mediated": false},
				{"program": "git", "name": "git", "arguments": ["push", "origin", "HEAD"], "mediated": false},
			],
		},
		"facts": {"red-head": red},
	}
	v.rule == "job read unread"
}

test_a_global_option_does_not_hide_the_push if {
	some v in violation with input as {
		"call": {
			"command": "git -C /work push",
			"programs": [{"program": "git", "name": "git", "arguments": ["-C", "/work", "push"], "mediated": false}],
		},
		"facts": {"red-head": red},
	}
	v.rule == "job read unread"
}

# Only the UNREAD failures are named: a read one is discharged.
test_only_unread_failures_are_named if {
	some v in violation with input as {
		"call": {
			"command": "git push",
			"programs": [{"program": "git", "name": "git", "arguments": ["push"], "mediated": false}],
		},
		"facts": {"red-head": {
			"head": "abc123",
			"failed": [{"id": "101", "name": "windows", "read": false}, {"id": "102", "name": "linux", "read": true}],
			"running": [],
		}},
	}
	v.subjects == [{"artifact": "windows job 101"}]
}

test_every_failure_read_admits_the_push if {
	count(violation) == 0 with input as {
		"call": {
			"command": "git push origin HEAD",
			"programs": [{"program": "git", "name": "git", "arguments": ["push", "origin", "HEAD"], "mediated": false}],
		},
		"facts": {"red-head": {
			"head": "abc123",
			"failed": [{"id": "101", "name": "windows", "read": true}],
			"running": ["macos"],
		}},
	}
}

test_a_running_check_alone_never_refuses if {
	count(violation) == 0 with input as {
		"call": {
			"command": "git push",
			"programs": [{"program": "git", "name": "git", "arguments": ["push"], "mediated": false}],
		},
		"facts": {"red-head": {"head": "abc123", "failed": [], "running": ["macos"]}},
	}
}

test_no_red_head_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {
			"command": "git push",
			"programs": [{"program": "git", "name": "git", "arguments": ["push"], "mediated": false}],
		},
		"facts": {"red-head": null},
	}
}

# A WORD IS NOT A SUBCOMMAND: `push` as a message or another git verb.
test_another_subcommand_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {
			"command": "git commit -m push",
			"programs": [{"program": "git", "name": "git", "arguments": ["commit", "-m", "push"], "mediated": false}],
		},
		"facts": {"red-head": red},
	}
	count(violation) == 0 with input as {
		"call": {
			"command": "git fetch origin",
			"programs": [{"program": "git", "name": "git", "arguments": ["fetch", "origin"], "mediated": false}],
		},
		"facts": {"red-head": red},
	}
}

test_another_tools_push_is_not_judged if {
	count(violation) == 0 with input as {
		"call": {
			"command": "hg push",
			"programs": [{"program": "hg", "name": "hg", "arguments": ["push"], "mediated": false}],
		},
		"facts": {"red-head": red},
	}
}
