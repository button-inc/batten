#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT language-unread|s@^\tnot names_shell(path)$@\tfalse@|every_shipped_preset_passes_its_own_suite
# A shell program says so in its NAME, not only in its first line.
#
# A file extension is the portable selector: every tool honours it, before
# opening the file, at no cost. A shebang is a CONTENT selector, so it works only
# for tools that read the first line and map it to a language — and a tool that
# does not covers nothing while reporting success. That failure is an exit `0`
# over a question nobody asked, which is the worst shape a gate can take.
#
# Measured against one tree carrying 143 such files: its own pre-commit runner
# reached them (shebang detection in the builtin's selector), a syntax matcher
# pointed at the directory scanned nothing and exited `0`, and an LSP with full
# bash support matched none of them because its filename matcher is extensions
# only. Two of the three were silently blind, independently, and neither
# announced it.
#
# Names no repository, no directory and no task: this is true of the practice,
# which is what a vendored preset may contain (non-negotiable rule 1). The
# consumer's `line_sources` glob decides which files are judged, and its
# `exclude` decides which are deliberate.
package batten.shell_hygiene

import rego.v1

rules contains "shebang-names-its-language"

# The interpreters worth naming. `env`-mediated and absolute spellings both
# reduce to the same question, so the match is on the interpreter word rather
# than on the line's shape.
shell_interpreters := {"sh", "bash", "dash", "zsh", "ksh"}

# A first line that declares a shell. Read from the LINES fact, so this decides
# over files no parser knows — which is the whole reason the fact exists.
declares_shell(path) if {
	line := input.tree.lines[path][0]
	startswith(line, "#!")
	some interpreter in shell_interpreters
	contains(line, interpreter)
}

# The name already says it. Both spellings, because a consumer that standardised
# on `.bash` is not wrong.
names_shell(path) if endswith(path, ".sh")

names_shell(path) if endswith(path, ".bash")

violation contains {
	"rule": "shebang-names-its-language",
	"verdict": "program name unnamed",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.lines
	declares_shell(path)
	not names_shell(path)
}

# The predicate's own tests (CLOUD-835's shape), and the allows are the
# load-bearing half: a rule that fired on everything would satisfy the denies
# alone.

test_an_extensionless_shell_program_is_named if {
	# A LITERAL, and it must stay one: this is the fixture the deny case rests on,
	# so a tree-wide rename that "helpfully" appended `.sh` here would turn the
	# deny test into a clean one and the suite would still be green.
	some v in violation with input as {"tree": {"lines": {"tools/deploy": ["#!/usr/bin/env bash", "set -euo pipefail"]}}}
	v.rule == "shebang-names-its-language"
}

test_an_absolute_interpreter_counts_too if {
	count(violation) == 1 with input as {"tree": {"lines": {"hooks/pre-commit": ["#!/bin/sh"]}}}
}

test_a_named_shell_program_is_clean if {
	count(violation) == 0 with input as {"tree": {"lines": {"install.sh": ["#!/usr/bin/env bash"]}}}
}

test_the_bash_spelling_is_clean_too if {
	count(violation) == 0 with input as {"tree": {"lines": {"lib/helpers.bash": ["#!/usr/bin/env bash"]}}}
}

# The discriminating case. A shebang that is not a shell must not be caught: a
# bats suite, a python program and a node script all carry one, and refusing them
# would make this a rule about shebangs rather than about shell.
test_another_language_is_not_this_rules_business if {
	count(violation) == 0 with input as {"tree": {"lines": {"tests/suite.bats": ["#!/usr/bin/env bats"]}}}
}

test_a_python_program_is_not_this_rules_business if {
	count(violation) == 0 with input as {"tree": {"lines": {"tools/report": ["#!/usr/bin/env python3"]}}}
}

# A file with no shebang at all is not a shell program, whatever its name.
test_a_plain_file_is_not_judged if {
	count(violation) == 0 with input as {"tree": {"lines": {"README.md": ["# Title"]}}}
}
