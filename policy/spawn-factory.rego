# spawn-factory: no function RETURNS a `std::process::Command` unless it is named
# here (CLOUD-1924).
#
# `clippy.toml` bans `std::process::Command` so that every spawn carries its own
# `#[expect(clippy::disallowed_types, reason = ...)]` stating its verdict — a
# spawn is an inventory row (CLOUD-320). A function that returns a `Command`
# moves that one `#[expect]` off every spawn and onto the factory: each caller is
# unannotated, the lint cannot see it, and the reason written once no longer
# describes what any caller runs. Measured on #962: `common::program(name) ->
# Command` under one generic reason laundered twelve spawns across eight tiers —
# `git`, `touch -d`, `sha256sum`, `mise`, `bash` — two of them GNU-only, and they
# turned the macOS leg red. The lint was green throughout, because the site it
# judges was the factory.
#
# WHY A NAMED ALLOWLIST RATHER THAN A MARKER. A `// spawn-factory:` comment on the
# line would let a change write its own permission. The list lives in this
# module, and `policy/**` is protected, so adding a factory takes an override
# admission whose answers land in the commit — an attributed decision in the
# diff, never a silent one.
#
# `-> Command` IS A SPAWN FACTORY ONLY WHERE THE FILE IMPORTS `std::process`'s.
# `surface.rs` and `spec.rs` build `clap::Command` trees and are not spawns; a
# file whose `use std::process::` line names `Command` is. The fully qualified
# `-> std::process::Command` is one wherever it appears.
#
# A SIGNATURE rustfmt BROKE ACROSS LINES still carries its return type on one
# line; the function it belongs to is the nearest `fn ` at or above it.
#
# NO INLINE REGEX, for the `[[pattern]]` rule: every test is a string builtin.
#
#MUTANT-SUITE crates/batten/tests/it/spawn_factory.rs
#MUTANT qualified-unseen|s@^returns_command(line, _) if contains(line, "-> std::process::Command")$@returns_command(line, _) if false@|a_factory_returning_the_qualified_command_is_refused
#MUTANT imported-unseen|s@^\tcontains(line, "-> Command")$@\tfalse@|a_factory_returning_the_imported_command_is_refused
#MUTANT allowlist-widened|s@^\tnot allowed(path, owner(lines, i))$@\ttrue@|a_named_factory_is_not_refused
#MUTANT clap-conflated|s@^\timports_std_command(lines)$@\ttrue@|a_clap_command_builder_is_not_a_spawn

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree.lines` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.spawn_factory

import rego.v1

rules contains "spawn bind loose"

# The factories that exist, each by the path and the `fn` line's prefix. Each one
# carries its own `#[expect]` naming the one program it builds.
allowlist := {
	"crates/batten/tests/it/common/mod.rs": [
		"pub(crate) fn batten()",
		"pub(crate) fn batten_at_real_root()",
		"pub(crate) fn git_command(",
		"pub(crate) fn task_bash(",
		"pub(crate) fn task_command(",
	],
	"crates/batten/tests/it/primitives.rs": ["fn raw("],
}

imports_std_command(lines) if {
	some line in lines
	startswith(trim_space(line), "use std::process::")
	contains(line, "Command")
}

returns_command(line, _) if contains(line, "-> std::process::Command")

returns_command(line, lines) if {
	contains(line, "-> Command")
	imports_std_command(lines)
}

# The `fn` line a return type belongs to: the nearest one at or above it.
owner(lines, i) := trim_space(lines[j]) if {
	j := max([k |
		some k, candidate in lines
		k <= i
		contains(candidate, "fn ")
	])
}

allowed(path, fn_line) if {
	some prefix in allowlist[path]
	startswith(fn_line, prefix)
}

in_scope(path) if {
	startswith(path, "crates/")
	endswith(path, ".rs")
}

violation contains {
	"rule": "spawn bind loose",
	"verdict": "spawn bind loose",
	"subjects": [{"path": path, "line": i + 1}],
} if {
	some path, lines in input.tree.lines
	in_scope(path)
	some i, line in lines
	returns_command(line, lines)
	not allowed(path, owner(lines, i))
}

# ---------------------------------------------------------------------------
# Load-time tier.
# ---------------------------------------------------------------------------

test_a_launcher_taking_the_program_is_refused if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/tests/it/common/mod.rs": [
		"use std::process::{Command, Output};",
		"pub(crate) fn program(name: &str) -> Command {",
		"    Command::new(name)",
		"}",
	]}}}
}

test_a_broken_signature_is_owned_by_its_fn if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/src/a.rs": [
		"pub fn spawner(",
		"    program: &str,",
		") -> std::process::Command {",
	]}}}
}

test_the_named_factories_pass if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/tests/it/common/mod.rs": [
		"use std::process::{Command, Output};",
		"pub(crate) fn git_command(dir: &Path, args: &[&str]) -> Command {",
	]}}}
}

test_clap_is_not_a_spawn if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/src/surface.rs": [
		"use clap::{Arg, ArgAction, Command};",
		"pub fn command() -> Command {",
	]}}}
}
