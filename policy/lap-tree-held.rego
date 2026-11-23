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
# LIVENESS IS THE LAP'S OWN READING, IN THE CHECKOUT THE CALL WRITES
# (CLOUD-2789). `input.facts["land-live"]` is the root of a checkout the call
# writes in (a program's directory as its own `-C`/`--git-dir`/`--manifest-path`
# moves it, a redirect's target, a write tool's target) whose `land` singleton
# lock names a pid that exists (`task::singleton_holder`): the reading `land`
# uses to refuse a second lap. A string while such a lap is live, null
# otherwise, so a call that writes no lap's checkout is never judged here.

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

# Or absolute and under the live lap's checkout root (CLOUD-2789): a redirect or
# a write tool naming `<root>/f` writes the lap's tree from wherever it runs,
# while `/dev/null` or another checkout's path lies under no live root.
inside(target) if {
	is_string(target)
	startswith(target, concat("", [input.facts["land-live"], "/"]))
}

held contains path if {
	input.call.operation == "write"
	path := input.call.writes
	inside(path)
}

# THE TARGET, NEVER THE TOKEN (#1276): `redirects` holds the raw tokens, so
# `2>/dev/null` and a lone `>` read as relative paths and every read that
# discarded its stderr was held. `redirect-writes` is the targets alone.
held contains target if {
	some segment in input.call.segments
	some target in segment["redirect-writes"]
	inside(target)
}

held contains sprintf("git %s", [program.subcommand]) if {
	some program in input.call.programs
	program.name == "git"
	program.subcommand in moving
}

# THE BOARD AND THE PULL REQUEST ARE READ BY THE GATE TOO (CLOUD-2785, decided on
# CLOUD-2781). Laps 6 and 10 on #1276 went red at `batten-check` because a row was
# FILED and the PR body edited while the lap ran: the gate read the board before
# the body closed the new row. So, while a lap is live, an issue creation (a
# `save_issue` with no `id`) and a pull-request edit carrying a `body` are held.
# A comment is not: no gate reads one. The same writes made through `batten mcp
# call` on a shell are held too (CLOUD-2789): the engine presents a mediated call
# as the tool it mediates, so `input.call.tool` and `input.call.arguments` read
# alike on both routes.
held contains "tracker issue create" if {
	endswith(input.call.tool, "__save_issue")
	not input.call.arguments.id
}

held contains "pull request body" if {
	endswith(input.call.tool, "__update_pull_request")
	input.call.arguments.body
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

live_lap := {"land-live": "/work/a"}

test_an_absolute_write_under_the_live_root_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {"operation": "write", "writes": "/work/a/src/x.rs"}}
	v.verdict == "path write held"
}

test_an_absolute_redirect_under_the_live_root_is_held if {
	some v in violation with input as {"facts": live_lap, "call": {"segments": [{"redirects": [">", "/work/a/out.txt"], "redirect-writes": ["/work/a/out.txt"]}]}}
	v.verdict == "path write held"
}

test_a_sibling_of_the_live_root_is_not_under_it if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"operation": "write", "writes": "/work/ab/src/x.rs"}}
}

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
	some v in violation with input as {"facts": live_lap, "call": {"segments": [{"redirects": [">", "out.txt"], "redirect-writes": ["out.txt"]}]}}
	v.verdict == "path write held"
}

test_a_redirect_outside_or_to_an_fd_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"segments": [{"redirects": ["2>/dev/null", "2>&1"], "redirect-writes": ["/dev/null"]}]}}
}

# THE OPERATOR TOKENS ALONE NEVER HOLD (#1276): an input redirection writes
# nothing, whatever its raw tokens look like.
test_an_input_redirect_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"segments": [{"redirects": ["<", "in.txt"], "redirect-writes": []}]}}
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
		"segments": [{"redirects": [], "redirect-writes": []}, {"redirects": [">", "out.txt"], "redirect-writes": ["out.txt"]}],
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

test_filing_an_issue_is_held_while_a_lap_is_live if {
	some v in violation with input as {"facts": live_lap, "call": {"tool": "mcp__Linear__save_issue", "arguments": {"title": "t"}}}
	v.verdict == "path write held"
}

test_editing_an_issue_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"tool": "mcp__Linear__save_issue", "arguments": {"id": "CLOUD-1"}}}
}

test_a_pull_request_body_edit_is_held_while_a_lap_is_live if {
	some v in violation with input as {"facts": live_lap, "call": {"tool": "mcp__github__update_pull_request", "arguments": {"body": "Closes CLOUD-1"}}}
	v.verdict == "path write held"
}

test_a_comment_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"tool": "mcp__Linear__save_comment", "arguments": {"body": "x"}}}
}

test_no_live_lap_admits_a_filing if {
	count(violation) == 0 with input as {"facts": {"land-live": null}, "call": {"tool": "mcp__Linear__save_issue", "arguments": {"title": "t"}}}
}

test_a_reading_git_command_is_admitted if {
	count(violation) == 0 with input as {"facts": live_lap, "call": {"programs": [{"name": "git", "subcommand": "log"}]}}
}
