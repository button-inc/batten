#!/usr/bin/env bats
# subject: mise-tasks/connector-verb-guard.sh
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
# implementation denies a verb this guard has no verdict on at all — the
# `closing-key-check` / `DO-NOT-CLOSE` hazard, which failed as the inverse of its
# author's intent rather than as a refusal.
#
# THOSE ROWS CHANGED SIDES IN CLOUD-790 AND ARE MORE LOAD-BEARING FOR IT. The
# guard used to pre-approve `unsubscribe_pr_activity`; it could not. The connector
# sets that tool to `always_ask`, and CLOUD-765 measured that a `PreToolUse` hook
# returning `allow` does not skip such a prompt — so the arm asserted an authority
# it did not hold while a human paid one click per landing. The arm is gone and
# `pr-unsubscribed drop` does the work off the mediated path entirely.
#
# So the unsubscribe rows now assert `none` — the guard gets out of the way — and
# they are the only rows that can catch either mutation: the one that re-adds the
# arm, and the one that would let the deny arm reach back across the `__` bound.
# With the allow arm gone that bound is the sole defence, which is why they stay.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/connector-verb-guard.sh"
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

@test "an unsubscribe under the readable name is left undecided" {
	# NOT pre-approved, and the difference is CLOUD-790's whole finding: the
	# connector sets this verb to `always_ask`, which a hook's `allow` cannot
	# skip. Claiming otherwise cost a human a click per landing while the file
	# read as having removed it.
	[ "$(decision mcp__github__unsubscribe_pr_activity)" = none ]
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

@test "an unsubscribe under a UUID server name is left undecided" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__unsubscribe_pr_activity)" = none ]
}

@test "a subscribe under a UUID server name is denied" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__subscribe_pr_activity)" = deny ]
}

@test "send_later under a UUID server name is denied" {
	[ "$(decision mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__send_later)" = deny ]
}

# --- the discrimination itself ------------------------------------------------

@test "the unsubscribe suffix is not swallowed by the subscribe suffix" {
	# Stated as its own row rather than left implicit above: with the allow arm
	# gone, the `__` bound on the deny arm is the ONLY thing keeping these two
	# apart, and a deny here would be the silent inverse-of-intent failure.
	[ "$(decision mcp__github__unsubscribe_pr_activity)" = none ]
	[ "$(decision mcp__github__subscribe_pr_activity)" = deny ]
}

@test "a verb with no server prefix is still decided" {
	# The bare-name arm has no `__` to bound it, so the discrimination there rests
	# on the case patterns alone — a separate reading of the same hazard.
	[ "$(decision unsubscribe_pr_activity)" = none ]
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

@test "the bypass silences every arm" {
	run bash -c "BATTEN_CONNECTOR_VERB_BYPASS=1 '$GUARD' <'$(payload mcp__github__subscribe_pr_activity)'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	run bash -c "BATTEN_CONNECTOR_VERB_BYPASS=1 '$GUARD' <'$(payload mcp__Claude_Code_Remote__send_later)'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- the coverage declaration `mcp-allow-check` binds to ----------------------

@test "--covers prints every suffix the guard decides, and nothing else" {
	run "$GUARD" --covers
	[ "$status" -eq 0 ]
	[ "$(printf '%s\n' "$output" | sort)" = "$(printf 'create_trigger\nsend_later\nsubscribe_pr_activity\n' | sort)" ]
}

@test "--covers-allow publishes the arm a connector control can override" {
	# Empty is the healthy state (CLOUD-790), and it must be an EMPTY SUCCESS
	# rather than an error: `mcp-allow-check` reads this to decide whether any
	# pre-approved suffix is one the live connector sets to `always_ask`, and a
	# non-zero exit there would read as "nothing to judge" when it means
	# "could not judge".
	run "$GUARD" --covers-allow
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "no suffix is published as pre-approved and denied at once" {
	# A suffix in both arms would make the file's verdict depend on arm order,
	# which is exactly the ambiguity the removed allow arm used to create.
	allow=$("$GUARD" --covers-allow)
	deny=$("$GUARD" --covers)
	while IFS= read -r suffix; do
		[ -n "$suffix" ] || continue
		! grep -qxF "$suffix" <<<"$deny"
	done <<<"$allow"
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
