#!/usr/bin/env bats
# fanout-guard's decision table (CLOUD-287): a subagent spawn's reading manifest
# and prompt budget as a PreToolUse verdict. Fixtures are real git trees, since
# the manifest conjunct intersects the prompt with `git ls-files`.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/fanout-guard"
	SETTINGS="$BATS_TEST_DIRNAME/../.claude/settings.json"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT/.serena/memories/workflow" "$ROOT/mise-tasks"
	git init -q "$ROOT"
	git -C "$ROOT" config user.email t@example.com
	git -C "$ROOT" config user.name t
	for f in AGENTS.md one.md two.md three.md four.md five.md; do
		echo x >"$ROOT/$f"
	done
	echo x >"$ROOT/mise-tasks/land"
	echo x >"$ROOT/.serena/memories/workflow/agent-fanout.md"
	git -C "$ROOT" add -A
	git -C "$ROOT" commit -qm x
	# The guard resolves `payload-field` beside itself and enumerates the tree it
	# is RUN IN, so the fixture is the cwd and the real script is the guard.
	#
	# THE DECODER IS STUBBED, through `payload-field`'s own documented seam —
	# "BATTEN_BIN exists so a bats suite can point this at a stub without a
	# rebuild". Not a convenience: `mutant` copies TRACKED FILES ONLY into a temp
	# tree, so there is no `target/` there and a resolved-from-PATH `batten`
	# predates this change's `prompt` field. Every prompt would decode as absent,
	# the deny cases would go red before any mutation, and the allow cases would
	# pass for the wrong reason — vacuously. This suite is about the guard's
	# LOGIC; that the binary decodes a spawn envelope is
	# `crates/batten/tests/cli.rs`'s claim, over the compiled binary, where it
	# belongs.
	write_decoder_stub
	export BATTEN_BIN="$BATS_TEST_TMPDIR/batten"
	cd "$ROOT" || return 1
}

# The two fields the guard reads, and nothing else — a stub that answered more
# would be asserting a vocabulary the real allowlist owns. A non-string prompt
# prints nothing, matching `Field::read`'s contract that it reads as ABSENT.
write_decoder_stub() {
	cat >"$BATS_TEST_TMPDIR/batten" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
name=""
while [ $# -gt 0 ]; do
	case "$1" in
	--name) name="$2" && shift 2 ;;
	*) shift ;;
	esac
done
raw=$(cat)
case "$name" in
tool-name) jq -r '.tool_name // empty' <<<"$raw" 2>/dev/null ;;
prompt) jq -r 'if (.tool_input.prompt | type) == "string" then .tool_input.prompt else empty end' <<<"$raw" 2>/dev/null ;;
esac
exit 0
STUB
	chmod +x "$BATS_TEST_TMPDIR/batten"
}

# A `Task` spawn envelope, the shape the hook is wired to.
spawn() {
	jq -nc --arg p "$1" \
		'{hook_event_name:"PreToolUse", tool_name:"Task",
		  tool_input:{description:"d", prompt:$p}}' | "$GUARD"
}

@test "an ordinary single-target spawn is allowed" {
	run spawn "Read AGENTS.md and fix the typo in it."
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a manifest over the cap is refused, naming the cap and the count" {
	run spawn "Required reading: AGENTS.md one.md two.md three.md four.md five.md"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]] ||
		[[ "$output" == *'"permissionDecision":"deny"'* ]]
	[[ "$output" == *"over the cap of 3"* ]]
	[[ "$output" == *"6 required-reading artifacts"* ]]
}

@test "a mem: reference counts as an artifact, resolved against the tree" {
	run spawn "Read mem:workflow/agent-fanout, AGENTS.md, one.md and two.md first"
	[ "$status" -eq 0 ]
	[[ "$output" == *"4 required-reading artifacts"* ]]
}

@test "a path-shaped token naming nothing tracked does not count" {
	# `origin/main`, a URL and a prose slash are the false positives an
	# allowlist would have had to enumerate; the tracked-tree intersection
	# drops them by construction.
	run spawn "Rebase on origin/main, see https://example.com/a/b, and read AGENTS.md — either/or."
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an oversize prompt is refused against the token budget" {
	long=$(printf 'x%.0s' $(seq 1 8000))
	run spawn "$long"
	[ "$status" -eq 0 ]
	[[ "$output" == *"over the budget of 1500"* ]]
}

@test "the caps are configurable in both directions" {
	BATTEN_FANOUT_READING_CAP=10 run spawn "AGENTS.md one.md two.md three.md four.md five.md"
	[ -z "$output" ]
	BATTEN_FANOUT_READING_CAP=1 run spawn "AGENTS.md one.md"
	[[ "$output" == *"over the cap of 1"* ]]
}

@test "a tool that is not a spawn is never judged" {
	run bash -c "jq -nc '{hook_event_name:\"PreToolUse\", tool_name:\"Bash\",
	                      tool_input:{command:\"cat AGENTS.md one.md two.md three.md four.md\"}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "unparseable stdin neither refuses nor errors" {
	run bash -c "printf 'not json' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an absent prompt fails open" {
	run bash -c "jq -nc '{hook_event_name:\"PreToolUse\", tool_name:\"Task\", tool_input:{}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass is honoured" {
	BATTEN_FANOUT_GUARD_BYPASS=1 run spawn "AGENTS.md one.md two.md three.md four.md five.md"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the refusal is a pointer — it carries no prompt bytes" {
	run spawn "SECRET-LITERAL-DO-NOT-PRINT: read AGENTS.md one.md two.md three.md four.md"
	[[ "$output" != *"SECRET-LITERAL-DO-NOT-PRINT"* ]]
	[[ "$output" == *"AGENTS.md"* ]]
}

@test "the Task hook is registered in settings, by shape" {
	# The SHAPE, not the substring: `mise run -q fanout-guard` and a by-path
	# registration satisfy a name match identically, and only one of them is
	# what `hook-pin-check` and the latency budget assume (CLOUD-479).
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
groups = [g for g in d['hooks']['PreToolUse'] if g.get('matcher') == 'Task']
assert groups, [g.get('matcher') for g in d['hooks']['PreToolUse']]
cmds = [h['command'] for g in groups for h in g['hooks']]
assert any(c.endswith('/mise-tasks/fanout-guard') for c in cmds), cmds
"
	[ "$status" -eq 0 ]
}
