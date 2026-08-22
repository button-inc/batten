#!/usr/bin/env bats
# subject: mise-tasks/batten-glob-check.sh
# CLOUD-224. `batten-check`'s glob is a second authority over a set batten.toml
# already defines, and a second authority narrows silently: add a `[[rule]]`
# whose glob names a path outside the list and the step simply stops running for
# commits that touch only that path, with nothing going red.
#
# This suite drives the containment check that closes that. The cases that
# matter are the ones where a gate can pass for the wrong reason — a parse that
# found nothing, a subsumption that is too generous — not the happy path.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/batten-glob-check.sh"
	CONFIG="$BATS_TEST_TMPDIR/batten.toml"
	HOOKS="$BATS_TEST_TMPDIR/hk.pkl"
}

# A batten.toml carrying one rule with the given glob, and nothing else this
# gate reads.
config_with_rule_glob() {
	printf '[[rule]]\nid = "r"\nkind = "forbid"\nglob = "%s"\npattern = "x"\nseverity = "deny"\nscope = "tree"\n' "$1" >"$CONFIG"
}

# An hk.pkl whose ["batten-check"] step globs exactly the given entries, wrapped
# the way `pkl format` wraps a long list.
hooks_with() {
	{
		printf '  ["some-other-step"] {\n    glob = List("never-read.txt")\n    check = "x"\n  }\n'
		printf '  ["batten-check"] {\n    depends = List("test")\n    glob =\n      List(\n'
		local g
		for g in "$@"; do
			printf '        "%s",\n' "$g"
		done
		printf '      )\n    check = "mise run batten-check"\n  }\n'
	} >"$HOOKS"
}

@test "the committed pair covers itself today" {
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a rule glob absent from the list is caught, and named" {
	config_with_rule_glob "scripts/**/*.py"
	hooks_with "crates/**" batten.toml

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"scripts/**/*.py"* ]]
	# Pointer: the file and the line that demands it, never file contents.
	[[ "$output" == *"$CONFIG:4:"* ]]
}

@test "a verbatim entry covers a rule glob" {
	config_with_rule_glob "mise.toml"
	hooks_with mise.toml

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 0 ]
}

@test "a P/** entry subsumes anything under P — the reason the list stays short" {
	config_with_rule_glob "crates/batten/tests/**/*.rs"
	hooks_with "crates/**"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 0 ]
}

@test "subsumption is a prefix test, so a sibling prefix does not count" {
	# `crates-extra/` is not under `crates/`. A looser string match would call
	# this covered, which is the direction a containment check must never fail in.
	config_with_rule_glob "crates-extra/**/*.rs"
	hooks_with "crates/**"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"crates-extra/**/*.rs"* ]]
}

@test "a budget file is an input, and an uncovered one is caught" {
	# The case the issue's own wording missed: a declared budget is a gate under
	# `check`, not only under `policy budget` (CLOUD-50), so AGENTS.md is as much
	# an input as any rule glob.
	printf '[[rule]]\nid = "r"\nkind = "forbid"\nglob = "mise.toml"\npattern = "x"\nseverity = "deny"\nscope = "tree"\n\n[budget.instructions]\nfiles = ["AGENTS.md", "CONTRIBUTING.md"]\nmax_tokens = 10\n' >"$CONFIG"
	hooks_with mise.toml AGENTS.md

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CONTRIBUTING.md"* ]]
	[[ "$output" != *"AGENTS.md"* ]]
}

@test "an embedded budget path is an input too" {
	printf '[[rule]]\nid = "r"\nkind = "forbid"\nglob = "mise.toml"\npattern = "x"\nseverity = "deny"\nscope = "tree"\n\n[[budget.instructions.embedded]]\npath = ".serena/project.yml"\nkey = "initial_prompt"\n' >"$CONFIG"
	hooks_with mise.toml

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *".serena/project.yml"* ]]
}

@test "a shape rule declares no glob and demands nothing" {
	printf '[[rule]]\nid = "s"\nkind = "shape"\nscope = "mediated_call"\nseverity = "deny"\npattern = "gh pr merge"\nreason = "no"\n\n[[rule]]\nid = "r"\nkind = "forbid"\nglob = "mise.toml"\npattern = "x"\nseverity = "deny"\nscope = "tree"\n' >"$CONFIG"
	hooks_with mise.toml

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 0 ]
}

@test "a config the gate parses nothing out of is exit 2, not a pass" {
	# The vacuous green a containment check produces most easily: parse zero
	# requirements and every list covers them. Distinguished from a violation,
	# the same way a missing lockfile is in lock-complete.
	printf '[epoch]\ntracked = ["batten.toml"]\n' >"$CONFIG"
	hooks_with "crates/**"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 2 ]
	[[ "$output" == *"parsed no rule glob"* ]]
}

@test "a batten-check step with no glob at all is a regression, not a default" {
	# Glob-less means unconditional, which is the state CLOUD-224 removed. A
	# containment check that read absence as "covers everything" would wave the
	# revert straight back through.
	config_with_rule_glob "mise.toml"
	printf '  ["batten-check"] {\n    depends = List("test")\n    check = "mise run batten-check"\n  }\n' >"$HOOKS"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"glob-less step runs on every commit"* ]]
}

@test "a comment inside the list is not list syntax, parenthesis and all" {
	# THE PARSE THAT LIED. Each entry in the committed list carries a comment
	# recording which rule made the path an input; one of them contained
	# `(CLOUD-614)`, and the `)` was read as the end of `List(` — so every entry
	# below it dropped out of `covered` and the gate reported four paths that had
	# been listed all along. Two entries here, the second reachable only if the
	# comment between them is skipped rather than terminating the list.
	config_with_rule_glob "mise.toml"
	{
		printf '  ["batten-check"] {\n    glob =\n      List(\n'
		printf '        "crates/**",\n'
		printf '        // a note about a rule (CLOUD-614) and why it is here\n'
		printf '        "mise.toml",\n'
		printf '      )\n    check = "mise run batten-check"\n  }\n'
	} >"$HOOKS"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 0 ]
}

@test "another step's glob list is not read as batten-check's" {
	# The file carries a dozen glob lists; only one belongs to this step.
	config_with_rule_glob "never-read.txt"
	hooks_with "crates/**"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"never-read.txt"* ]]
}

@test "a missing input file is exit 2, distinct from a violation" {
	config_with_rule_glob "mise.toml"

	run "$GATE" "$CONFIG" "$BATS_TEST_TMPDIR/absent.pkl"
	[ "$status" -eq 2 ]
}

@test "output is a pointer — no file contents echoed" {
	config_with_rule_glob "scripts/**/*.py"
	hooks_with "crates/**"

	run "$GATE" "$CONFIG" "$HOOKS"
	[ "$status" -eq 1 ]
	[[ "$output" != *"severity = "* ]]
	[[ "$output" != *"pattern = "* ]]
}
