#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT write-mode-unchecked|s@^\tinput.call\["permission-mode"\] == "auto"$@\ttrue@|an_edit_is_not_preapproved_in_default_mode
#MUTANT write-destructive-granted|s@^\t\tnot destructive_program(program)$@\t\ttrue@|a_destructive_shell_write_is_left_to_the_host_in_auto
#MUTANT memory-write-ungranted|s@^\tmemory_write_tool(input.call.tool)$@\tfalse@|a_memory_write_is_preapproved_outside_plan_mode
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

# A MEMORY WRITE IS A WRITE BATTEN ALREADY ALLOWS, and this arm was missing
# (CLOUD-2313). `.serena/memories/**` is protected against every file tool and
# its `[[redirect]]` row sends the writer to Serena's memory tools, so these are
# the only route a memory changes by. An MCP call never matched `write_tool`, so
# every memory edit batten had passed was put to the owner. Measured 2026-10-15:
# `edit_memory` prompted on a module-map row.
#
# NAMED TOOLS, NOT A VERB SHAPE OVER EVERY SERVER: a connector's writes (a
# tracker comment, a session dispatch) stay with the host and the dispatch
# receipt. `delete_memory` is left to the host as destructive.
#
# EVERY MODE BUT PLAN, which is the one exception to this file's auto-only rule,
# and it is the owner's (2026-10-16): memory edits are "supposed to be always
# approved by batten". Auto already grants them through `auto-mode-is-preapproved`,
# so an auto-only arm changed nothing; the session that measured the prompt ran
# in default mode. Plan mode refuses writes before any grant is asked.
preapprove contains "call grant now" if {
	input.call.event == "pre-tool"
	memory_write_tool(input.call.tool)
	input.call["permission-mode"] != "plan"
}

memory_write_tool(tool) if tool in {"mcp__serena__write_memory", "mcp__serena__edit_memory", "mcp__serena__rename_memory"}

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

test_a_memory_write_is_granted_in_default_and_auto if {
	every mode in ["default", "auto", "acceptEdits"] {
		"call grant now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__serena__edit_memory", "permission-mode": mode}}
	}
}

test_a_memory_write_is_not_granted_in_plan if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__serena__write_memory", "permission-mode": "plan"}}
}

test_a_memory_delete_and_a_connector_write_are_left_to_the_host if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__serena__delete_memory", "permission-mode": "default"}}
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__Linear__save_comment", "permission-mode": "default"}}
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

# A compound line is judged program by program, so `rm` in the second segment
# withholds the grant as surely as `rm` alone: the case `module-tested-bare-only`
# asks every mediated module for (CLOUD-857).
test_a_later_segment_rm_withholds_the_grant if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "cd /x && python3 y.py && rm -rf build",
		"segments": [{"words": ["cd", "/x"]}, {"words": ["python3", "y.py"]}, {"words": ["rm", "-rf", "build"]}],
		"programs": [program("cd", ["/x"]), program("python3", ["y.py"]), program("rm", ["-rf", "build"])],
	}}
}

test_a_compound_write_is_granted if {
	"call grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "cd /x && python3 y.py | tee out.log",
		"segments": [{"words": ["cd", "/x"]}, {"words": ["python3", "y.py"]}, {"words": ["tee", "out.log"]}],
		"programs": [program("cd", ["/x"]), program("python3", ["y.py"]), program("tee", ["out.log"])],
	}}
}

test_a_destructive_batten_verb_is_left_to_the_host if {
	count(preapprove) == 0 with input as shell("auto", [{"name": "batten", "arguments": ["target", "prune"], "batten-effect": "destructive"}])
}
