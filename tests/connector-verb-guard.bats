#!/usr/bin/env bats
# CLOUD-178. The guard that decides the harness-connector verbs by tool-name
# SUFFIX, so the verdict survives the exposed server name changing.
#
# THE SPINE OF THIS SUITE IS THE UUID ROWS. A permission rule in
# `.claude/settings.json` names its server as a literal, and the host re-exposes a
# connector under a UUID after a reconnect — measured on `main` at `d671184`,
# where `mcp__Claude_Code_Remote__*` grants sat inert while the live tools were
# `mcp__bf7c680d-…__*`. A suite that only exercises the readable spelling grades
# the case that already worked and says nothing about the one that did not.
#
# THE SECOND SPINE IS THE UN/SUBSCRIBE DISCRIMINATION.
# `unsubscribe_pr_activity` ends with `subscribe_pr_activity`, so the natural
# implementation denies the call the guard exists to permit — the
# `closing-key-check` / `DO-NOT-CLOSE` hazard, which failed as the inverse of its
# author's intent rather than as a refusal. The `#MUTANT` on the guard drops the
# allow arm precisely so those rows must go red.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/connector-verb-guard"
}

# The payload goes through a FILE and the helper prints its path — embedding JSON
# into a `bash -c` string lets the shell reinterpret its braces before the guard
# sees it, which `issue-search-guard.bats` records as having failed nine of
# fifteen rows there.
payload() {
	jq -nc --arg t "$1" '{tool_name: $t}' >"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}

decision() {
	run bash -c "'$GUARD' <'$(payload "$1")'"
	[ "$status" -eq 0 ]
	# No output at all is the third verdict: the guard got out of the way and the
	# ordinary permission flow decides.
	if [ -z "$output" ]; then
		printf 'none\n'
		return 0
	fi
	jq -r '.hookSpecificOutput.permissionDecision' <<<"$output"
}

# --- the verbs, under the readable spelling -----------------------------------

@test "an unsubscribe under the readable name is pre-approved" {
	[ "$(decision mcp__github__unsubscribe_pr_activity)" = allow ]
}

@test "a subscribe under the readable name is denied" {
	[ "$(decision mcp__github__subscribe_pr_activity)" = deny ]
}

@test "send_later under the readable name is denied" {
	[ "$(decision mcp__Claude_Code_Remote__send_later)" = deny ]
}

@test "create_trigger under the readable name is denied" {
	[ "$(decision mcp__Claude_Code_Remote__create_trigger)" = deny ]
}

# --- the same verbs under a UUID: the rows a permission rule cannot reach ------

@test "an unsubscribe under a UUID server name is pre-approved" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__unsubscribe_pr_activity)" = allow ]
}

@test "a subscribe under a UUID server name is denied" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__subscribe_pr_activity)" = deny ]
}

@test "send_later under a UUID server name is denied" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__send_later)" = deny ]
}

# --- the discrimination itself ------------------------------------------------

@test "the unsubscribe suffix is not swallowed by the subscribe suffix" {
	# Stated as its own row rather than left implicit in the rows above: this is
	# the one property the mutation removes, and it must fail loudly when it does.
	[ "$(decision mcp__github__unsubscribe_pr_activity)" = allow ]
	[ "$(decision mcp__github__subscribe_pr_activity)" = deny ]
}

@test "a verb with no server prefix is still decided" {
	[ "$(decision unsubscribe_pr_activity)" = allow ]
	[ "$(decision subscribe_pr_activity)" = deny ]
}

@test "a tool merely CONTAINING a decided verb is not decided" {
	# Left-bounded on `__`: a host tool called `resubscribe_pr_activity_v2` or
	# `describe_pr_activity` is somebody else's question, and a guard that
	# swallowed it would be the over-match that gets a guard switched off.
	[ "$(decision mcp__github__subscribe_pr_activity_v2)" = none ]
	[ "$(decision mcp__github__resubscribe_pr_activity)" = none ]
}

# --- everything it cannot establish, and the bypass ---------------------------

@test "an unrelated tool gets no decision" {
	[ "$(decision mcp__Linear__save_issue)" = none ]
	[ "$(decision Bash)" = none ]
}

@test "a payload with no tool_name gets no decision" {
	printf '{}' >"$BATS_TEST_TMPDIR/empty.json"
	run bash -c "'$GUARD' <'$BATS_TEST_TMPDIR/empty.json'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "unparseable stdin gets no decision rather than a deny" {
	printf 'not json at all' >"$BATS_TEST_TMPDIR/junk.json"
	run bash -c "'$GUARD' <'$BATS_TEST_TMPDIR/junk.json'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass silences every arm, including the allow" {
	run bash -c "BATTEN_CONNECTOR_VERB_BYPASS=1 '$GUARD' <'$(payload mcp__github__subscribe_pr_activity)'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	run bash -c "BATTEN_CONNECTOR_VERB_BYPASS=1 '$GUARD' <'$(payload mcp__github__unsubscribe_pr_activity)'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- the coverage declaration `mcp-allow-check` binds to ----------------------

@test "--covers prints every suffix the guard decides, and nothing else" {
	run "$GUARD" --covers
	[ "$status" -eq 0 ]
	[ "$(printf '%s\n' "$output" | sort)" = "$(printf 'create_trigger\nsend_later\nsubscribe_pr_activity\nunsubscribe_pr_activity\n' | sort)" ]
}

@test "every deny rule in the committed settings names a covered suffix" {
	# The pairing `mcp-allow-check` enforces, asserted here too so the guard's own
	# suite fails if a deny rule is added to the settings without coverage — the
	# defect this whole change exists to stop being silent.
	covers=$("$GUARD" --covers)
	while IFS= read -r rule; do
		[ -n "$rule" ] || continue
		suffix=${rule##*__}
		grep -qxF "$suffix" <<<"$covers" ||
			{
				echo "deny rule $rule names suffix $suffix, which no guard covers" >&2
				return 1
			}
	done < <(jq -r '[.permissions.deny // [] | .[] | select(startswith("mcp__"))] | .[]' \
		"$BATS_TEST_DIRNAME/../.claude/settings.json")
}
