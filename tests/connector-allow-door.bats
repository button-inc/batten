#!/usr/bin/env bats
# subject: mise-tasks/connector-allow-guard.sh, through `batten hook`
#
# THE SECOND TIER, and the tier that finds this class. `tests/connector-allow-
# guard.bats` runs the script directly and reads what it printed; that is the
# bash equivalent of a Rego module's `with input as`, and
# `.claude/rules/policy-modules.md` names its failure exactly — it fabricates the
# shape the ENGINE may be unable to consume, so a guard can pass its own suite
# green while the door discards every verdict it produces.
#
# WHICH IS WHAT HAPPENED. `connector-allow-guard` retired from a direct
# `PreToolUse` registration into a `[[hook.handler]]` row (CLOUD-312 row 5) and
# kept writing `hookSpecificOutput` on stdout. Behind the door that is
# `Violation::ImpersonatedHost`: reported on stderr, never forwarded. Measured
# 2026-08-26 on this repository's live wiring — the guard's deny document was
# dropped and the refusal the host received came from an unrelated engine row
# that happens to cover the same tool. Every deny in the committed permission
# table is covered that way, which is precisely why nothing went red.
#
# EVERY CASE RUNS AGAINST A FIXTURE REPOSITORY CARRYING ONE ROW: the handler and
# nothing else. That isolation is the whole design. Driving the real
# `batten.toml` would let another rule's verdict stand in for this one — which is
# the exact substitution that hid the defect for the life of the migration.

setup() {
	# Resolved as `tests/run-shape.bats` resolves it: $BATTEN_BIN, then release,
	# then debug, then PATH. CI has no release build when `test:bats` runs, and a
	# shorter chain aborts setup under bats' `set -e` before the skip can fire.
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

	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/mise-tasks"
	# Copied from the suite's own tree, so `mise run mutant` reaches this tier
	# too: under `mutant` that tree is the mutated one.
	cp "$BATS_TEST_DIRNAME/../mise-tasks/connector-allow-guard.sh" "$REPO/mise-tasks/"
	cp "$BATS_TEST_DIRNAME/../mise-tasks/connector-allow-resolve.sh" "$REPO/mise-tasks/"

	# ONE ROW. No `[[rule]]` at all, so nothing in the engine can produce a
	# verdict of its own and be mistaken for the handler's.
	{
		echo "version = 1"
		echo
		echo "[[hook.handler]]"
		echo 'id = "connector-allow-guard"'
		echo 'on = "pre-tool"'
		echo 'run = ["mise-tasks/connector-allow-guard.sh"]'
		echo 'matcher = "^mcp__"'
		echo "timeout_ms = 5000"
		echo 'owner = "CLOUD-312"'
		echo 'expires = "2027-02-28"'
	} >"$REPO/batten.toml"
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"

	# THE DENIED VERB IS ONE NO ENGINE ROW COVERS. `send_later` would have been
	# the natural fixture and is the wrong one: this repository's own
	# `no-scheduled-self-wakeup` refuses it, so a case built on it passes whether
	# the handler spoke or not. That substitution is the defect, not a detail.
	export BATTEN_MCP_SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	cat >"$BATTEN_MCP_SETTINGS" <<-'JSON'
		{"permissions":{
		  "allow":["mcp__Claude_Code_Remote__create_session"],
		  "deny":["mcp__Claude_Code_Remote__archive_session"]
		}}
	JSON
	export BATTEN_MCP_CONFIG="$BATS_TEST_TMPDIR/mcp-config.json"
	cat >"$BATTEN_MCP_CONFIG" <<-'JSON'
		{"mcpServers":{
		  "bbbbbbbb-5555-6666-7777-888888888888":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta"}
		}}
	JSON
}

# Hand one mediated call to the engine and keep the two streams apart: the
# verdict is on stdout, and the door reports a contract violation on stderr.
# Merging them is how a dropped verdict reads as a delivered one.
#
# CALLED DIRECTLY, NEVER THROUGH `run`. `run` executes its argument in a
# subshell, so the two variables set here would be discarded and every case
# would compare an EMPTY string against a `!= *…*` pattern and pass. Measured on
# this suite's first execution: four of five cases went green that way and the
# fifth — the one asserting a POSITIVE substring — was the only thing that
# noticed. A suite whose rows are all negative assertions cannot tell you that.
door() { # door <tool_name>
	local envelope
	envelope=$(jq -nc --arg t "$1" '{hook_event_name:"PreToolUse",tool_name:$t,tool_input:{}}')
	(
		cd "$REPO" || exit 1
		printf '%s' "$envelope" | "$BIN" hook --harness claude-code \
			>"$BATS_TEST_TMPDIR/door.out" 2>"$BATS_TEST_TMPDIR/door.err"
	)
	DOOR_OUT=$(cat "$BATS_TEST_TMPDIR/door.out")
	DOOR_ERR=$(cat "$BATS_TEST_TMPDIR/door.err")
}

@test "THE MEASURED DEFECT: the door forwards no host document the handler wrote" {
	# The one row that would have caught the migration. It is stated over the
	# violation line rather than over the verdict, because the verdict was
	# available from another rule and the violation line never is.
	door mcp__bbbbbbbb-5555-6666-7777-888888888888__archive_session
	[[ "$DOOR_ERR" != *"wrote a host decision document"* ]]
	[[ "$DOOR_ERR" != *"hook.handler connector-allow-guard:"* ]]
}

@test "a committed deny reaches the host as the engine's own refusal" {
	door mcp__bbbbbbbb-5555-6666-7777-888888888888__archive_session
	[[ "$DOOR_OUT" == *'"permissionDecision":"deny"'* ]]
	# Rendered BY the engine and attributed to the handler — which is the
	# difference between a verdict that travelled and one the guard printed.
	[[ "$DOOR_OUT" == *"hook.handler.connector-allow-guard"* ]]
	[[ "$DOOR_OUT" == *archive_session* ]]
	# Non-negotiable 4 survives the extra hop: the live key must not travel.
	[[ "$DOOR_OUT" != *bbbbbbbb* ]]
}

@test "a committed allow is read as advice, and lands where an advisory lands" {
	# The half the door has no channel for (CLOUD-898), pinned at exactly what it
	# does rather than at what it should do. A row asserting `permissionDecision:
	# "allow"` would be asserting a channel that does not exist; a row asserting
	# only "not denied" would pass over the dropped document this suite exists to
	# refuse, AND over a handler that never ran.
	#
	# MEASURED, and it corrects the reading this suite was first written against:
	# an advisory the host has no model-facing surface for is NOT discarded — it
	# goes to the engine's own stderr, where on this host at this event it is
	# transcript-only rather than model-facing. Inert for the prompt CLOUD-191
	# exists to remove, and visible to a human reading the session. Those are
	# different things and the row says which one it is asserting.
	door mcp__bbbbbbbb-5555-6666-7777-888888888888__create_session
	[[ "$DOOR_OUT" != *'"deny"'* ]]
	[[ "$DOOR_ERR" == *"already allows create_session on Claude_Code_Remote"* ]]
	[[ "$DOOR_ERR" != *"wrote a host decision document"* ]]
	# Non-negotiable 4 holds on this stream too.
	[[ "$DOOR_ERR" != *bbbbbbbb* ]]
}

@test "the impersonation detector is live behind this row, not merely defined" {
	# THE POSITIVE CONTROL, and this suite is worth little without it: every other
	# row here asserts the ABSENCE of a violation line, and absence is also what a
	# handler that never ran produces. So one row makes the handler write the host
	# document on purpose and requires the door to say so, by name.
	#
	# `interpret`'s own unit case pins the same predicate. It could not catch the
	# defect this suite exists for, because what was wrong was a committed handler
	# ROW rather than the interpreter — which is why this is stated here, over the
	# real dispatch, against the real binary.
	cat >"$REPO/mise-tasks/connector-allow-guard.sh" <<-'SH'
		#!/usr/bin/env bash
		printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}\n'
	SH
	chmod +x "$REPO/mise-tasks/connector-allow-guard.sh"
	door mcp__bbbbbbbb-5555-6666-7777-888888888888__archive_session
	[[ "$DOOR_ERR" == *"hook.handler connector-allow-guard: wrote a host decision document"* ]]
	# And the refusal it tried to write did NOT become one.
	[[ "$DOOR_OUT" != *'"deny"'* ]]
}

@test "a name the guard cannot resolve leaves the call undecided" {
	# The load-bearing negative: a guard that refused everything would satisfy the
	# deny row above and be useless (CLOUD-418).
	door mcp__cccccccc-9999-0000-1111-222222222222__archive_session
	[[ "$DOOR_OUT" != *'"deny"'* ]]
	[[ "$DOOR_ERR" != *"hook.handler connector-allow-guard:"* ]]
}

@test "a non-MCP tool never reaches the handler at all" {
	# `matcher` is what keeps a narrowed handler from costing a process on every
	# call it is silent on, and a matcher that selects everything is expressible
	# by accident. Asserted through the door because `selects_tool` is the
	# engine's, not the script's.
	door Bash
	[[ "$DOOR_OUT" != *'"deny"'* ]]
	[ -z "$DOOR_ERR" ]
}
