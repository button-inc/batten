#!/usr/bin/env bats
# subject: mise.toml
# CLOUD-104. JSON and non-workflow YAML had no syntax or format gate at all:
# `prettier` was globbed to `**/*.md` plus `action.yml`, so six hand-edited
# harness configs — `.claude/settings.json`, `.mcp.json`, `.codex/hooks.json`,
# `.cursor/hooks.json`, `.gemini/settings.json`, `.github/hooks/batten.json` —
# were parsed only by whichever content gate happened to read one first. A
# malformed one does not fail loudly; it silently disables a hook.
#
# WHAT THESE CASES PIN, and why each is here rather than assumed:
#
# 1. The gate is green on the committed tree. Without this the rest can pass
#    over a repository that is already failing.
# 2. It reds on a corrupt file at a COVERED path, and greens again when that
#    file goes away — CLOUD-418's shown-able-to-fail, in both directions,
#    because a gate that cannot discriminate ships as coverage.
# 3. It stays GREEN on a corrupt file at an EXCLUDED path. This is the one that
#    justifies the pathspec: `lint:toml` feeds taplo `git ls-files` because
#    `target/` holds deliberately corrupt TOML the suite writes, and "a gate
#    that fails on its own test data is a gate someone switches off". The same
#    hazard exists here in JSON — `cursor-bom.json` exists to carry a BOM and a
#    fuzz corpus entry is an input, not a document.
#
# `git add -N` in cases 2 and 3 is not incidental: the task selects from
# `git ls-files`, so an untracked file is invisible to it. Registering intent to
# add is what puts the probe inside the selection, and it also demonstrates that
# the selection IS the tracked set rather than a tree walk.

setup() {
	REPO="$BATS_TEST_DIRNAME/.."
	COVERED="$REPO/lint-deno-probe.json"
	EXCLUDED="$REPO/crates/batten/tests/fixtures/hooks/lint-deno-probe.json"
}

teardown() {
	# Both probes are removed from the index AND the worktree on every exit path,
	# including a failing one — a leftover probe would red every later run of the
	# gate and read as a real finding.
	for f in "$COVERED" "$EXCLUDED"; do
		[ -e "$f" ] || continue
		(cd "$REPO" && git rm -q --cached --force "${f#"$REPO"/}" 2>/dev/null) || true
		rm -f "$f"
	done
}

@test "lint:deno is green on the committed tree" {
	run mise run lint:deno
	[ "$status" -eq 0 ]
}

@test "a corrupt file at a covered path reds it, and removing it greens again" {
	printf '{ this is not json,,,' >"$COVERED"
	(cd "$REPO" && git add -N lint-deno-probe.json)
	run mise run lint:deno
	[ "$status" -ne 0 ]

	(cd "$REPO" && git rm -q --cached --force lint-deno-probe.json)
	rm -f "$COVERED"
	run mise run lint:deno
	[ "$status" -eq 0 ]
}

@test "a corrupt file under tests/fixtures leaves it green" {
	printf '{ this is not json,,,' >"$EXCLUDED"
	(cd "$REPO" && git add -N crates/batten/tests/fixtures/hooks/lint-deno-probe.json)
	run mise run lint:deno
	[ "$status" -eq 0 ]
}

@test "the task pins --prose-wrap=preserve, which is a predicate and not a style" {
	# The default (`always`, width 80) reflows AGENTS.md past
	# `[budget.instructions]`'s `max_lines`, so `policy-budget` would red on line
	# count alone. Asserted against the task body rather than by reformatting,
	# because the cheap check is that nobody quietly drops the flag.
	run mise tasks info lint:deno
	[ "$status" -eq 0 ]
	[[ "$output" == *"--prose-wrap=preserve"* ]]
}

@test "the hk step calls this task rather than re-deriving the file set" {
	# A comment is not a call site: the step must actually invoke the task, or
	# the hook and the task can disagree about what passes. Asserted over the
	# step block itself, bounded by the next step header.
	run awk '/^  \["deno-fmt"\]/ { s = 1 } s && /mise run lint:deno/ { found = 1 } s && /^  \["/ && !/deno-fmt/ { s = 0 } END { exit !found }' "$REPO/hk.pkl"
	[ "$status" -eq 0 ]
}
