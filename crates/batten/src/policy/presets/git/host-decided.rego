#MUTANT-SUITE crates/batten/tests/it/git_preset.rs
#MUTANT reset-subcommand-unread|s@^\tprogram.subcommand == "reset"$@\tfalse@|a_global_option_never_hides_a_destructive_git_call
#MUTANT clean-restore-ungranted|s@^\tcount(status.pathspecs) > 0$@\tfalse@|a_checkout_of_a_clean_tracked_file_is_granted
#MUTANT dirty-restore-granted|s@^\t\tp.clean == true$@\t\ttrue@|a_checkout_of_a_dirty_file_is_left_to_the_host
#MUTANT bare-restore-granted|s@^\tprogram.subcommand == "restore"$@\tfalse@|a_bare_restore_of_a_dirty_file_is_left_to_the_host
#MUTANT untracked-restore-granted|s@^\t\tp.tracked == true$@\t\ttrue@|a_checkout_of_an_untracked_path_is_left_to_the_host
#MUTANT glob-restore-granted|s@^\t\tp.literal == true$@\t\ttrue@|a_globbed_or_directory_pathspec_is_left_to_the_host
# The git calls the host decides: what discards work and has no batten
# alternative (CLOUD-2057, CLOUD-2684), stated once and read by every grant.
#
# ONE PREDICATE, TWO READERS (CLOUD-2768). The git preset's own grant withholds
# itself from these calls, and the `claude-code-cloud` mode grant, which grants
# every call batten allowed, yields on them. With the predicate only in the git
# module, the mode grant pre-approved `git clean -fdx` and `git reset --hard`
# that the git preset deliberately left to the host. This module ships in BOTH
# presets' bundles, so neither reads a copy of the other's judgement.
#
# NEVER A DENIAL. A call this names is neither granted nor refused: refusing it
# would be a dead end, and granting it would decide a loss nobody asked about.
#
# Each arm reads the subcommand the engine projects past git's own options
# (CLOUD-2354), never a copy of git's option table.
package batten.git_host

import rego.v1

# `status` is the engine's `pathspec-status` fact, `null` where the call names
# no checkout or restore or one it cannot place.
host_decides(program, _) if {
	program.name == "git"
	destructive(program)
}

host_decides(program, status) if {
	program.name == "git"
	discards(program, status)
}

# Some program in `call` is one the host decides. A permission event may carry
# no programs, and then nothing here holds.
call_decided(call, status) if {
	some program in object.get(call, "programs", [])
	host_decides(program, status)
}

has(arguments, flag) if flag in arguments

has_prefix(arguments, prefix) if {
	some word in arguments
	startswith(word, prefix)
}

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

# DISCARDING WORKING-TREE CHANGES, decided by what is at the paths
# (CLOUD-2684): a checkout or restore of literal, tracked, clean pathspecs loses
# nothing; anything else is the host's. `null` never reads as clean. A restore
# needs no `--`.
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

# --- cases ---------------------------------------------------------------

git(subcommand, rest) := {
	"name": "git", "arguments": array.concat([subcommand], rest),
	"subcommand": subcommand,
}

test_a_hard_reset_is_the_hosts if {
	host_decides(git("reset", ["--hard", "HEAD~1"]), null)
}

test_a_soft_reset_is_not if {
	not host_decides(git("reset", ["--soft", "HEAD~1"]), null)
}

test_a_dirty_restore_is_the_hosts if {
	host_decides(git("restore", ["f"]), {"pathspecs": [{"path": "f", "literal": true, "tracked": true, "clean": false}]})
}

test_a_clean_restore_is_not if {
	not host_decides(git("restore", ["f"]), {"pathspecs": [{"path": "f", "literal": true, "tracked": true, "clean": true}]})
}

test_a_compound_line_is_the_hosts_by_its_git_program if {
	call_decided({"command": "cd /x && git reset --hard", "programs": [
		{"name": "cd", "arguments": ["/x"]},
		git("reset", ["--hard"]),
	]}, null)
	not call_decided({"command": "cd /x && git status", "programs": [
		{"name": "cd", "arguments": ["/x"]},
		git("status", []),
	]}, null)
}

test_another_program_is_never_the_hosts_here if {
	not host_decides({"name": "rm", "arguments": ["-rf", "x"], "subcommand": "clean"}, null)
}
