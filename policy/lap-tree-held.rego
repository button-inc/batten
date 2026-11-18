#MUTANT-SUITE crates/batten/tests/it/land_lap.rs
#MUTANT live-lap-edit-admitted|s@^\tis_string(input.facts\["land-live"\])$@\tfalse@|a_write_into_the_checkout_is_held_while_a_lap_is_live
#
# CLOUD-2781. A lap's gate dispatches every stage against the WORKING TREE, so a
# write made while it runs reaches the stages still to come, and the verdict the
# lap records judges a tree no stage saw whole. Measured on #1276: this row's own
# first step was being written in the checkout while lap 3's later stages ran.
#
# Two mechanisms, one each side of the gate. `land::verify` VOIDS a gate whose
# HEAD or dirty count moved by its return (`land::tree_moved`); that is the sound
# backstop and catches any write, by any route. This module is the prevention:
# it refuses, before it runs, each write the call model exposes:
#
#   * a write tool aimed inside the checkout. `call.writes` is repo-relative
#     wherever the target is inside the repository and absolute outside it
#     (`Envelope::relativise_writes`), so "inside" is "not absolute";
#   * a shell redirect to a relative target, the shell write the call model
#     names (a Bash call carries no `call.writes`);
#   * a `git` subcommand that moves HEAD or the index.
#
# STATED GAP, not a hidden one: an in-place shell writer with no redirect (`sed
# -i`, `cp` onto a tracked file) exposes no target here. The void catches it at
# the gate's return, except an edit reverted before the gate returns.
#
# LIVENESS IS THE LAP'S OWN READING. `input.facts["land-live"]` is the pid the
# `land` singleton lock names, when that pid exists (`task::singleton_holder`):
# the reading `land` uses to refuse a second lap. A string while a lap is live,
# null otherwise, so a call outside a lap is never judged here.

# METADATA
# description: |
#   Refuse a write into the checkout while a `land` lap holds it. Bound to the
#   MEDIATED-CALL surface: `input.facts["land-live"]` and `input.call` are that
#   surface's. THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE
#   `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.lap_tree_held

import rego.v1

rules contains "path write held"

# HEAD- and index-moving git subcommands: each rewrites what the gate reads.
moving := {"commit", "reset", "checkout", "switch", "rebase", "merge", "cherry-pick", "revert", "stash", "am", "restore", "add", "rm", "mv", "apply"}

live if {
	is_string(input.facts["land-live"])
}

# A target inside the checkout: repo-relative, never absolute, and never an fd
# duplication such as `&1`.
inside(target) if {
	is_string(target)
	not startswith(target, "/")
	not startswith(target, "&")
}

held contains path if {
	input.call.operation == "write"
	path := input.call.writes
	inside(path)
}

held contains target if {
	some segment in input.call.segments
	some target in segment.redirects
	inside(target)
}

held contains sprintf("git %s", [program.subcommand]) if {
	some program in input.call.programs
	program.name == "git"
	program.subcommand in moving
}

violation contains {
	"rule": "path write held",
	"verdict": "path write held",
	"subjects": [{"path": subject} | some subject in held],
} if {
	live
	count(held) > 0
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------

live_lap := {"land-live": "4242"}

test_a_write_inside_the_checkout_is_held_while_a_lap_is_live if {
	some v in violation with input as {"facts": live_lap, "call": {"operation": "write", "writes": "src/a.rs"}}
	v.verdict == "path write held"
}

test_a_write_outside_the_checkout_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"operation": "write", "writes": "/tmp/scratch/a.md"}}
}

test_no_live_lap_admits_every_write if {
	count(violation) == 0 with input as {"facts": {"land-live": null}, "call": {"operation": "write", "writes": "src/a.rs"}}
}

test_a_relative_redirect_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {"segments": [{"redirects": ["out.txt"]}]}}
	v.verdict == "path write held"
}

test_a_redirect_outside_or_to_an_fd_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"segments": [{"redirects": ["/dev/null", "&1"]}]}}
}

test_a_head_moving_git_command_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {"programs": [{"name": "git", "subcommand": "commit"}]}}
	v.verdict == "path write held"
}

# COMPOUND, because real commands are (CLOUD-857): the write sits in the SECOND
# segment and the git commit in the second program, so a module that read only
# the first word of the line would admit both.
test_a_redirect_after_a_list_operator_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {
		"command": "cd src && echo x > out.txt",
		"segments": [{"redirects": []}, {"redirects": ["out.txt"]}],
	}}
	v.verdict == "path write held"
}

test_a_commit_after_a_list_operator_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {
		"command": "git status; git commit -m wip",
		"programs": [{"name": "git", "subcommand": "status"}, {"name": "git", "subcommand": "commit"}],
	}}
	v.verdict == "path write held"
}

test_a_reading_git_command_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"programs": [{"name": "git", "subcommand": "log"}]}}
}
