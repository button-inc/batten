#!/usr/bin/env bats
# subject: policy/run-shape.rego
#
# The negative-control suite for the first migrated gate (CLOUD-843 track 2).
#
# IT DRIVES THE COMPILED BINARY OVER A REAL ENVELOPE, and that is the whole
# point rather than a convenience. `batten policy test` is established as
# insufficient evidence (CLOUD-845): `with input as` lets a module's own test
# fabricate a shape the engine cannot produce, so a module can pass its suite
# green and gate nothing. Every case here goes in through `batten hook` — the
# same door a mediated call comes through — and reads the permission decision
# the host would read.
#
# The fixture is a throwaway git repository carrying ONE row and a copy of the
# module under test, so the predicate is exercised in isolation from this
# repository's other rules, and `mise run mutant` reaches it: the copy is taken
# from the suite's own tree, which under `mutant` is the mutated one.

setup() {
	load helpers

	# Resolved the way `payload-field` and `tests/stop-guard.bats` resolve it —
	# $BATTEN_BIN, then release, then debug, then PATH — rather than a shorter
	# chain of this file's own. Measured on this branch's first CI run: there is
	# no release build when `test:bats` runs there, and `BIN="$(command -v
	# batten)"` under bats' `set -e` ABORTED setup before the skip below could
	# fire, so all 13 cases went red over a binary that was simply somewhere
	# else. The debug arm is what keeps these controls running in CI rather than
	# skipping there, which for a suite whose whole job is proving the gate
	# decides would be coverage evaporating exactly where it counts.
	BIN=""
	for candidate in \
		"${BATTEN_BIN:-}" \
		"$BATS_TEST_DIRNAME/../target/release/batten" \
		"$BATS_TEST_DIRNAME/../target/debug/batten"; do
		[ -n "$candidate" ] && [ -x "$candidate" ] || continue
		BIN="$candidate"
		break
	done
	[ -n "$BIN" ] || BIN="$(command -v batten || true)"
	[ -n "$BIN" ] || skip "no batten binary to drive"

	MODULE="$BATS_TEST_DIRNAME/../policy/run-shape.rego"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/policy"
	cp "$MODULE" "$REPO/policy/run-shape.rego"
	{
		echo "version = 1"
		echo
		echo "[[rule]]"
		echo 'id = "commit-message-obtainable"'
		echo 'kind = "policy"'
		echo 'scope = "mediated_call"'
		echo 'module = "policy/run-shape.rego"'
		echo 'severity = "deny"'
	} >"$REPO/batten.toml"
	# No global or system config: a contributor's own git settings must not be
	# able to change a verdict here (CLOUD-282).
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"
}

# Build the Claude Code PreToolUse envelope and hand it to the engine. Python
# does the JSON quoting because these commands carry quotes, newlines and
# heredocs, which is exactly what the predicate is about.
hook() { # hook <command>
	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "$1")
	(cd "$REPO" && printf '%s' "$envelope" | "$BIN" hook --harness claude-code)
}

denied() { [[ "$1" == *'"permissionDecision":"deny"'* ]]; }
allowed() { [[ "$1" != *'"deny"'* ]]; }

# --- the predicate ----------------------------------------------------------

@test "THE MEASURED SHAPE: a git commit naming no message source is denied" {
	# `pre-commit` runs before git asks for a message, so this spends the whole
	# gate and then blocks on $EDITOR with nobody to close it (CLOUD-488).
	run hook 'git commit'
	denied "$output"
	run hook 'git commit -a'
	denied "$output"
}

@test "every form that CAN obtain a message stays allowed" {
	# The load-bearing half. A predicate that only ever denied would satisfy the
	# case above and be useless (CLOUD-418).
	local c
	for c in 'git commit -F /tmp/msg.txt' \
		'git commit -m "a message"' \
		'git commit -am "a message"' \
		'git commit --amend --no-edit' \
		'git commit --fixup HEAD' \
		'git commit -C HEAD@{1}' \
		'git commit --message=hello' \
		'git commit -F -'; do
		run hook "$c"
		allowed "$output"
	done
}

# --- the list, which is where a raw-string module goes silent ---------------

@test "a compound list is judged per element, not by its first word" {
	# THE SHAPE A RAW-STRING MODULE MISSES. The vendored `no-force-push` preset
	# anchors on `words[0] == "git"` over the whole command, so `cd /tmp && git
	# push --force` reaches it as `cd` and is allowed — green tests, silent
	# gate. Every element is a command here.
	run hook 'cd /tmp && git commit'
	denied "$output"
	run hook 'git add -A && git commit -m x'
	allowed "$output"
}

@test "a pipe stage is judged too" {
	run hook 'echo hi | git commit'
	denied "$output"
}

@test "a wrapper is looked through to the program it runs" {
	run hook 'timeout 300 git commit'
	denied "$output"
	run hook 'timeout 300 git commit -m x'
	allowed "$output"
}

# --- scrubbing: prose is not a call ----------------------------------------

@test "a git commit inside a quoted span is prose, not a call" {
	# This repository writes the shape down constantly — in commit messages, in
	# issue bodies, in this file. A module judging the raw string would refuse
	# its own documentation.
	run hook 'echo "git commit"'
	allowed "$output"
	run hook "echo 'git commit'"
	allowed "$output"
}

@test "a quoted span carrying a list separator is not a list" {
	# THE CASE THAT DISCRIMINATES the quote scrub. A quoted mention with no
	# separator in it is already safe by the program anchoring above; what needs
	# the scrub is a message that carries a `;` or `&&`, because the list split
	# would otherwise turn the tail of a commit message into its own command.
	# Both quote characters, because they are two passes.
	run hook 'echo "step one; git commit -x"'
	allowed "$output"
	run hook "echo 'step one; git commit -x'"
	allowed "$output"
}

@test "a git commit inside a heredoc body is prose, not a call" {
	run hook "$(printf 'cat > t.bats <<%s\ngit commit\n%s\n' BATS BATS)"
	allowed "$output"
}

@test "an unquoted mention does not resolve to git" {
	# The anchoring, without which `echo git commit` reads as a call.
	run hook 'echo git commit'
	allowed "$output"
}

@test "a heredoc or redirect bound to this element is a message source" {
	run hook "$(printf 'git commit -F - <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	allowed "$output"
	run hook 'git commit -F - < /tmp/msg.txt'
	allowed "$output"
}

# --- the refusal itself -----------------------------------------------------

@test "the refusal names its predicate and the remedy that cannot rebind" {
	# A migrated gate keeps its remedy text (CLOUD-437): a `msg` that lost it in
	# translation is a regression no `policy test` would catch. A policy deny
	# carries `Fix::None`, so the remedy has to live in the module's own prose.
	run hook 'git commit'
	[[ "$output" == *"commit-names-no-message-source"* ]]
	[[ "$output" == *'-F <path>'* ]]
	[[ "$output" == *"pre-commit"* ]]
}

@test "git -C <path> commit is a deliberate false negative, carried over" {
	# The bash guard resolved `sub1` to the path and let it through, because a
	# guard with false positives gets bypassed (CLOUD-199) and this repository
	# commits from its own root. A migration that silently fixed it would be
	# changing the predicate, not moving it.
	run hook 'git -C /some/path commit'
	allowed "$output"
}

@test "a command with no git commit in it at all is untouched" {
	run hook 'ls -la'
	allowed "$output"
	run hook 'hg commit'
	allowed "$output"
}
