#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT write-mode-unchecked|s@^\tinput.call\["permission-mode"\] == "auto"$@\ttrue@|an_edit_is_not_preapproved_in_default_mode
#MUTANT write-destructive-granted|s@^\t\tnot destructive_program\(program\)$@\t\ttrue@|a_destructive_shell_write_is_left_to_the_host_in_auto
# In auto mode every write batten allows is put to no one (CLOUD-2002).
#
# The owner's rule, 2026-09-29: "Write operations are supposed to be allowed by
# batten in auto, and read in all modes." The reads half is `call read now`
# (`read-only-is-preapproved`). This is the writes half. `call grant now` used
# to cover only `batten` lifecycle verbs, and `program grant now` only git
# (`git-call-is-preapproved`). So an Edit, a Write, or a shell write that every
# batten rule had already passed was left to the host's auto-mode classifier.
# Measured 2026-10-03: the classifier denied an Edit to
# `.claude/commands/plan-fleet.md` that batten had allowed, and the session
# stopped.
#
# SOUND BY CONSTRUCTION, for the reason `git-call-is-preapproved` gives: the
# engine asks a `preapprove` rule only after its own decision came back Allow
# (`compose` in `lib.rs`, deny first). Every protected path, receipt, claim and
# shape row has already had its say, so this module adds no second judgement of
# the write. It only stops throwing the first one away.
#
# AUTO MODE ONLY. Plan mode refuses every write (`plan-mode-refuses-writes`),
# and default mode keeps the host's own prompt.
#
# DESTRUCTIVE CALLS ARE LEFT TO THE HOST, NEVER DENIED. A shell line carrying a
# program that discards data or processes is neither granted nor refused here,
# so the host asks. git is left to `git-call-is-preapproved`, which already
# knows which git calls discard work.
package batten.claude_code_cloud

import rego.v1

rules contains "call grant now"

preapprove contains "call grant now" if {
	input.call.event == "pre-tool"
	write_tool(input.call.tool)
	input.call["permission-mode"] == "auto"
}

preapprove contains "call grant now" if {
	input.call.event == "pre-tool"
	input.call.tool == "Bash"
	input.call["permission-mode"] == "auto"
	count(input.call.programs) > 0
	every program in input.call.programs {
		not destructive_program(program)
	}
}

write_tool(tool) if tool in {"Edit", "Write", "MultiEdit", "NotebookEdit"}

# What discards data or processes with no batten alternative, by program name.
# git is excluded so its calls are judged by the git preset alone.
destructive_program(program) if program.name in {
	"rm", "rmdir", "shred", "dd", "truncate", "wipefs", "mkfs",
	"kill", "pkill", "killall", "shutdown", "reboot", "halt", "sudo", "git",
}

destructive_program(program) if startswith(program.name, "mkfs.")

destructive_program(program) if program["batten-effect"] == "destructive"

# --- cases ---------------------------------------------------------------

shell(mode, programs) := {"call": {
	"event": "pre-tool", "tool": "Bash", "permission-mode": mode,
	"command": "x",
	"segments": [{"words": ["x"]}],
	"programs": programs,
}}

program(name, arguments) := {"name": name, "arguments": arguments, "batten-effect": null}

test_an_edit_is_granted_in_auto if {
	"call grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Edit", "permission-mode": "auto",
		"arguments": {"file_path": "README.md"},
	}}
}

test_an_edit_is_not_granted_in_default if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Edit", "permission-mode": "default",
		"arguments": {"file_path": "README.md"},
	}}
}

test_a_write_is_not_granted_in_plan if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Write", "permission-mode": "plan",
		"arguments": {"file_path": "README.md"},
	}}
}

test_a_shell_write_is_granted_in_auto if {
	"call grant now" in preapprove with input as shell("auto", [program("python3", ["x.py"])])
}

test_rm_is_left_to_the_host if {
	count(preapprove) == 0 with input as shell("auto", [program("python3", ["x.py"]), program("rm", ["-rf", "x"])])
}

test_git_is_left_to_the_git_preset if {
	count(preapprove) == 0 with input as shell("auto", [program("git", ["reset", "--hard"])])
}

test_a_destructive_batten_verb_is_left_to_the_host if {
	count(preapprove) == 0 with input as shell("auto", [{"name": "batten", "arguments": ["target", "prune"], "batten-effect": "destructive"}])
}
