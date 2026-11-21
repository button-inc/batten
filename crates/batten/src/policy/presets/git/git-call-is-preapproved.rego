#MUTANT-SUITE crates/batten/tests/it/git_preset.rs
#MUTANT git-ungranted|s@^\tgit_call(program)$@\tfalse@|an_everyday_git_call_is_granted
#MUTANT destructive-granted|s@^\tnot destructive(program)$@\ttrue@|a_destructive_git_call_is_left_to_the_host
#MUTANT reset-subcommand-unread|s@^\tprogram.subcommand == "reset"$@\tfalse@|a_global_option_never_hides_a_destructive_git_call
#MUTANT clean-restore-ungranted|s@^\tcount(status.pathspecs) > 0$@\tfalse@|a_checkout_of_a_clean_tracked_file_is_granted
#MUTANT dirty-restore-granted|s@^\t\tp.clean == true$@\t\ttrue@|a_checkout_of_a_dirty_file_is_left_to_the_host
#MUTANT bare-restore-granted|s@^\tprogram.subcommand == "restore"$@\tfalse@|a_bare_restore_of_a_dirty_file_is_left_to_the_host
#MUTANT untracked-restore-granted|s@^\t\tp.tracked == true$@\t\ttrue@|a_checkout_of_an_untracked_path_is_left_to_the_host
#MUTANT glob-restore-granted|s@^\t\tp.literal == true$@\t\ttrue@|a_globbed_or_directory_pathspec_is_left_to_the_host
#MUTANT plan-granted|s@^\tnot input.call\["permission-mode"\] == "plan"$@\ttrue@|a_git_write_is_not_granted_in_plan_mode
# Every git call batten allows is put to no one (CLOUD-2057).
#
# THE MEASURED DEADLOCK. A lap rebased a branch and its gate refused, so the
# head was unpushed; a write gate then refused every edit until the head was
# pushed; the push — an explicit `--force-with-lease=<ref>:<sha>` every batten
# rule allows — was then denied by the host's auto-mode classifier, which ruled
# over the host's own `Bash(git:*)` allow. Batten had judged the call and kept
# the verdict to itself.
#
# SOUND BY CONSTRUCTION, and only because of WHEN this runs: the engine asks a
# `preapprove` rule only after its own decision came back Allow (`compose` in
# `lib.rs`, deny first). Every git rule batten carries — the leased push, force
# to trunk, history drop, the rebase that belongs to the landing loop — has
# already had its say, so this module adds no second judgement of git. It only
# stops throwing the first one away.
#
# DESTRUCTIVE CALLS ARE LEFT TO THE HOST, NEVER DENIED. A call that discards
# work with no batten alternative is neither granted nor refused here: refusing
# it would be a dead end, and granting it would decide a loss nobody asked
# about. The host asks, as it does for a `destructive` batten verb.
package batten.git

import rego.v1

rules contains "program grant now"

preapprove contains "program grant now" if {
	input.call.event == "pre-tool"
	input.call.tool == "Bash"
	not input.call["permission-mode"] == "plan"
	count(input.call.programs) > 0
	some first in input.call.programs
	first.name == "git"
	every program in input.call.programs {
		granted(program)
	}
	not some_output_redirect(input.call)
}

granted(program) if {
	git_call(program)
	not destructive(program)
	not pushes_to_trunk(program)
	not discards(program, object.get(input, ["facts", "pathspec-status"], null))
}

granted(program) if program.name == "cd"

granted(program) if program["batten-effect"] in {"read", "write"}

git_call(program) if {
	program.name == "git"
}

# FUNCTIONS, NEVER RULES: a module-level value computed under one `test_`'s
# `with input as` answers the live call too (`read-only-is-preapproved.rego`).
some_output_redirect(call) if {
	is_array(call.segments)
	some segment in call.segments
	segment["output-redirect"]
}

some_output_redirect(call) if {
	not is_array(call.segments)
}

has(arguments, flag) if flag in arguments

has_prefix(arguments, prefix) if {
	some word in arguments
	startswith(word, prefix)
}

# What discards work and has no batten alternative. Stated once, here. Each
# reads the subcommand the engine projects past git's own options
# (CLOUD-2354), never a copy of git's option table.
destructive(program) if {
	program.subcommand == "clean"
	some word in program.arguments
	regex.match(`^(-[a-zA-Z]*f[a-zA-Z]*|--force)$`, word)
}

destructive(program) if {
	program.subcommand == "branch"
	some word in program.arguments
	regex.match(`^(-[a-zA-Z]*D[a-zA-Z]*)$`, word)
}

destructive(program) if {
	program.subcommand == "branch"
	has(program.arguments, "--delete")
	has(program.arguments, "--force")
}

destructive(program) if {
	program.subcommand == "push"
	some word in program.arguments
	word in {"--delete", "-d"}
}

# `git push origin :feat` deletes `feat`.
destructive(program) if {
	program.subcommand == "push"
	some word in program.arguments
	startswith(word, ":")
}

destructive(program) if {
	program.subcommand == "reset"
	has(program.arguments, "--hard")
}

# DISCARDING WORKING-TREE CHANGES, decided by what is at the paths
# (CLOUD-2684): a checkout or restore of literal, tracked, clean pathspecs loses
# nothing, so it is granted; anything else is left to the host. The fact is the
# engine's `pathspec-status`, `null` where the call names no such program or one
# it cannot place, and `null` never reads as clean. A restore needs no `--`.
discards(program, status) if {
	program.subcommand == "checkout"
	some word in program.arguments
	word in {"--", "."}
	not clean_pathspecs(status)
}

discards(program, status) if {
	program.subcommand == "restore"
	not clean_pathspecs(status)
}

clean_pathspecs(status) if {
	is_array(status.pathspecs)
	count(status.pathspecs) > 0
	every p in status.pathspecs {
		p.literal == true
		p.tracked == true
		p.clean == true
	}
}

destructive(program) if {
	program.subcommand == "stash"
	some word in program.arguments
	word in {"drop", "clear"}
}

destructive(program) if {
	program.subcommand == "worktree"
	has(program.arguments, "remove")
	has_prefix(program.arguments, "--force")
}

destructive(program) if {
	program.subcommand == "update-ref"
	has(program.arguments, "-d")
}

destructive(program) if {
	program.subcommand == "reflog"
	has(program.arguments, "expire")
}

destructive(program) if {
	program.subcommand == "gc"
	has_prefix(program.arguments, "--prune")
}

destructive(program) if program.subcommand == "filter-branch"

# A push that names the trunk lands without the landing loop's gate and CI, so it
# is the host's to ask about rather than this module's to wave through. The trunk
# is the consumer's `trunk-branch` `[[pattern]]` (rule 1: the preset names no
# branch). THE BOUND, stated: a bare `git push` while standing on the trunk names
# no refspec, and argv cannot see the current branch.
pushes_to_trunk(program) if {
	program.subcommand == "push"
	pattern := data.batten.patterns["trunk-branch"]
	some word in program.arguments
	not startswith(word, "-")
	parts := split(word, ":")
	name := trim_prefix(trim_prefix(parts[count(parts) - 1], "+"), "refs/heads/")
	regex.match(pattern, name)
}

# --- cases ---------------------------------------------------------------

call(mode, command, programs) := {"call": {
	"event": "pre-tool", "tool": "Bash", "permission-mode": mode,
	"command": command,
	"segments": [{"words": split(command, " ")}],
	"programs": programs,
}}

# The projected keys, written by hand: computing them here would be a copy of
# the parser the engine owns (CLOUD-2354).
git(globals, subcommand, rest) := {
	"name": "git", "batten-effect": null,
	"arguments": array.concat(array.concat(globals, [subcommand]), rest),
	"subcommand": subcommand, "global-options": globals,
}

test_a_leased_push_is_granted if {
	"program grant now" in preapprove with input as call("auto", "git push --force-with-lease=feat:abc origin feat", [git([], "push", ["--force-with-lease=feat:abc", "origin", "feat"])])
}

test_a_commit_is_granted if {
	"program grant now" in preapprove with input as call("default", "git commit -m x", [git([], "commit", ["-m", "x"])])
}

test_cd_then_git_is_granted if {
	"program grant now" in preapprove with input as call("auto", "cd /x && git status", [
		{"name": "cd", "arguments": ["/x"], "batten-effect": null},
		git([], "status", []),
	])
}

test_plan_mode_grants_no_git if {
	count(preapprove) == 0 with input as call("plan", "git commit -m x", [git([], "commit", ["-m", "x"])])
}

test_a_hard_reset_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("auto", "git reset --hard HEAD~1", [git([], "reset", ["--hard", "HEAD~1"])])
}

test_a_soft_reset_is_granted if {
	"program grant now" in preapprove with input as call("auto", "git reset --soft HEAD~1", [git([], "reset", ["--soft", "HEAD~1"])])
}

test_a_forced_clean_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("auto", "git clean -fdx", [git([], "clean", ["-fdx"])])
}

test_a_branch_delete_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("auto", "git push origin --delete feat", [git([], "push", ["origin", "--delete", "feat"])])
}

test_a_global_option_does_not_hide_the_subcommand if {
	count(preapprove) == 0 with input as call("auto", "git -C /x reset --hard", [git(["-C", "/x"], "reset", ["--hard"])])
}

test_git_beside_an_unknown_program_is_not_granted if {
	count(preapprove) == 0 with input as call("auto", "git status && rm -rf x", [
		git([], "status", []),
		{"name": "rm", "arguments": ["-rf", "x"], "batten-effect": null},
	])
}

test_a_redirect_is_not_granted if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "git log > f",
		"segments": [{"words": ["git", "log"], "output-redirect": true}],
		"programs": [git([], "log", [])],
	}}
}

trunk := {"trunk-branch": "^main$"}

test_a_push_to_the_trunk_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("auto", "git push origin main", [git([], "push", ["origin", "main"])])
		with data.batten.patterns as trunk
}

test_a_refspec_onto_the_trunk_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("auto", "git push origin HEAD:refs/heads/main", [git([], "push", ["origin", "HEAD:refs/heads/main"])])
		with data.batten.patterns as trunk
}

test_a_push_to_a_branch_is_granted_beside_a_trunk if {
	"program grant now" in preapprove with input as call("auto", "git push -u origin feat", [git([], "push", ["-u", "origin", "feat"])])
		with data.batten.patterns as trunk
}

# CLOUD-2684: a clean, tracked, literal pathspec is granted; anything else, and
# an absent fact, is left to the host.
pathspec_call(command, programs, status) := {
	"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": command,
		"segments": [{"words": split(command, " ")}],
		"programs": programs,
	},
	"facts": {"pathspec-status": status},
}

clean_f := {"pathspecs": [{"path": "f", "literal": true, "tracked": true, "clean": true}]}

test_a_clean_checkout_is_granted if {
	"program grant now" in preapprove with input as pathspec_call("git checkout HEAD -- f", [git([], "checkout", ["HEAD", "--", "f"])], clean_f)
}

test_a_dirty_restore_is_left_to_the_host if {
	count(preapprove) == 0 with input as pathspec_call("git restore f", [git([], "restore", ["f"])], {"pathspecs": [{"path": "f", "literal": true, "tracked": true, "clean": false}]})
}

test_a_restore_with_no_fact_is_left_to_the_host if {
	count(preapprove) == 0 with input as call("default", "git restore f", [git([], "restore", ["f"])])
}

test_a_directory_checkout_is_left_to_the_host if {
	count(preapprove) == 0 with input as pathspec_call("git checkout HEAD -- docs", [git([], "checkout", ["HEAD", "--", "docs"])], {"pathspecs": [{"path": "docs", "literal": false, "tracked": true, "clean": true}]})
}
