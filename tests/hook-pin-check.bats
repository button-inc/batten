#!/usr/bin/env bats
# subject: mise-tasks/hook-pin-check.sh
# CLOUD-479. The issue's own trap, made computable.
#
# Registering a hook by path saves ~185ms of task-runner startup per call and
# costs one thing that is easy to miss: a by-path invocation does not get mise's
# env, so a `[tools]`-pinned executable resolves to whatever the ambient PATH
# holds, or to nothing. Every hook in this repo is fail-open, so an absent tool
# does not error — it ALLOWS. A gate reporting a clean session while checking
# nothing is worse than the latency it saved, and nothing turns red.
#
# Every case drives the real script against fixture files, because the gate's
# whole job is reading committed text and there is nothing else to stub.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/hook-pin-check.sh"
	SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	MANIFEST="$BATS_TEST_TMPDIR/mise.toml"
	TASKS="$BATS_TEST_TMPDIR/mise-tasks"
	mkdir -p "$TASKS"
	printf '[tools]\n"aqua:jqlang/jq" = "1.7"\nzizmor = "1.29.0"\n' >"$MANIFEST"
}

gate() {
	HOOK_PIN_SETTINGS="$SETTINGS" HOOK_PIN_MANIFEST="$MANIFEST" HOOK_PIN_TASKS="$TASKS" \
		run "$GATE"
}

# A settings file registering one hook with the given command.
registers() { printf '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"%s"}]}]}}\n' "$1" >"$SETTINGS"; }

task() {
	printf '#!/usr/bin/env bash\n%s\n' "$2" >"$TASKS/$1"
	chmod +x "$TASKS/$1"
}

@test "a by-path hook shelling out to a pinned tool is refused, and both are named" {
	task guard 'raw=$(cat); printf "%s" "$raw" | jq -r ".x"'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"guard jq"* ]]
}

@test "the refusal names all three ways out, since a deny with no exit is a wall" {
	task guard 'jq -r ".x" <<<"{}"'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[[ "$output" == *"mise run"* ]]
	[[ "$output" == *"payload-field"* ]]
	[[ "$output" == *"PIN-OK"* ]]
}

@test "THE SAME TASK VIA mise run IS FINE — the pairing is the defect, not the tool" {
	# The negative self-test, and the one that makes this gate discriminate. A
	# `mise run` registration gets mise's env by construction, so the identical
	# script depending on the identical tool is correct there. A check that
	# refused both would just be "no hook may use jq", which is a different and
	# wrong rule.
	task guard 'jq -r ".x" <<<"{}"'
	registers 'mise run -q guard'
	gate
	[ "$status" -eq 0 ]
	[[ "$output" != *"guard jq"* ]]
}

@test "a by-path hook using no pinned tool passes" {
	task guard 'grep -q x /dev/null || true'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 0 ]
}

@test "a DECLARED exemption passes, because the script asserts the tool itself" {
	# `mcp-attach-check` is the case that forced this: its `jq` reads a settings
	# file and an MCP log, neither of which any payload extractor can serve, so
	# the honest answer is to assert the dependency loudly rather than pretend it
	# is not there. The declaration lives beside that assertion.
	task guard '#PIN-OK: jq
command -v jq >/dev/null || exit 0
jq -r ".x" <<<"{}"'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 0 ]
}

@test "an exemption for a DIFFERENT tool does not cover this one" {
	task guard '#PIN-OK: zizmor
jq -r ".x" <<<"{}"'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"guard jq"* ]]
}

@test "MENTIONING a tool in a comment is not depending on it" {
	# Load-bearing rather than cosmetic: `stop-guard` and `contract-drift` now
	# carry paragraphs explaining why they DROPPED jq, and a gate that read those
	# as a dependency would refuse the very change it exists to reward.
	task guard '# jq was dropped here on purpose; see payload-field.
printf "%s" ok'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 0 ]
}

@test "a tool named as a substring of another word is not a call" {
	task guard 'echo "jquery is not jq" >/dev/null'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 0 ]
}

@test "the pinned set is READ from the manifest, not restated here" {
	# Pinning a tool must enrol it with no second edit, or the gate goes stale
	# the first time someone adds one.
	printf '[tools]\n"aqua:koalaman/shellcheck" = "0.11.0"\n' >"$MANIFEST"
	task guard 'shellcheck x'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"guard shellcheck"* ]]
}

@test "no by-path registrations SAYS SO rather than reading as a clean pass" {
	# CLOUD-418's class: a gate that judged nothing must not look like one that
	# found nothing.
	task guard 'jq -r ".x" <<<"{}"'
	registers 'mise run -q guard'
	gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"no by-path hook registration"* ]]
}

@test "a missing settings file is exit 2, not a pass" {
	rm -f "$SETTINGS"
	gate
	[ "$status" -eq 2 ]
}

@test "a manifest with no [tools] is exit 2 — could not look, never a verdict" {
	printf '[env]\nX = "1"\n' >"$MANIFEST"
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[ "$status" -eq 2 ]
}

@test "output is pointer-only — the task and the tool, never a line of either file" {
	task guard 'SECRETXYZZY=1; jq -r ".x" <<<"{}"'
	registers '$CLAUDE_PROJECT_DIR/mise-tasks/guard.sh'
	gate
	[[ "$output" != *"SECRETXYZZY"* ]]
}

@test "this repository's own registrations pass" {
	# The live assertion. Every hook in `.claude/settings.json` is by-path since
	# CLOUD-479, so this is the case that would have caught the four guards that
	# already paired by-path invocation with pinned `jq` before anyone looked.
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"none depending on a mise-pinned tool"* ]]
}
