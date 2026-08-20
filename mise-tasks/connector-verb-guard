#!/usr/bin/env bash
#MISE description="PreToolUse hook body: decide the harness-connector verbs AGENTS.md already rules on, by tool-name SUFFIX, so the verdict survives the exposed server name changing (CLOUD-178)"
#
# CLOUD-178. A `.claude/settings.json` permission rule must name its server as a
# LITERAL — `mcp-allow-check` refuses a glob in that segment, correctly, because
# the CLI skips such a rule with a warning and it grants nothing. But a claude.ai
# connector's exposed name is chosen per registration episode by the HOST:
# readable at session start (`mcp__Linear__save_issue`), a UUID after a reconnect
# (`mcp__4db58e41-…__save_issue`). The literal that would match the second is an
# account-specific identifier, which non-negotiable rule 1 keeps out of committed
# config.
#
# So a permission rule cannot express these verdicts portably. CLOUD-178 concluded
# from that "no gate is possible for this one". That conclusion was wrong, and the
# counter-example was already shipping beside it: `issue-read-guard` and
# `board-move-guard` match `*save_issue` on the SUFFIX and never read the server
# segment at all. This file is that idiom applied to the verbs AGENTS.md rules on.
#
# MEASURED 2026-08-19, and it is why this exists rather than a fifth permission
# rule. `.claude/settings.json` on `main` allows `mcp__Claude_Code_Remote__*` and
# `mcp__Linear__*`; in the session that landed it the host exposed those same two
# connectors as `mcp__bf7c680d-…__*` and `mcp__cc451d34-…__*`, so
# `…__get_session` and `…__list_comments` both answered "requires approval" from
# inside an allow list that reads as covering them. A second literal spelling is
# still a literal.
#
# WHAT IT DECIDES, and every one is an existing AGENTS.md rule rather than a new
# one this file invents:
#
#   subscribe_pr_activity     DENY   — "No heartbeats … to babysit a PR."
#   send_later                DENY   — "No heartbeats (`send_later`/Routines/
#   create_trigger            DENY     timers) to babysit a PR … the ban is on
#                                      timers."
#
# The last two already sit in `permissions.deny` under a literal server name, and
# that is precisely the shape measured inert above: a deny that under-matches
# reads as a prohibition and enforces NOTHING. An allow that under-matches fails
# the other way — into a prompt a human sees — which is why `mcp-allow-check`'s
# new predicate binds denies and not allows.
#
# THE ALLOW ARM IS GONE, AND ITS REMOVAL IS THE FINDING (CLOUD-790). This file
# used to pre-approve `unsubscribe_pr_activity`, on the reasoning that dropping a
# subscription only narrows what reaches the session and that `land`'s
# `pr-unsubscribed` gate requires the drop before a runner is spent — so it must
# never wait on an approval. The reasoning was sound and the mechanism did not
# work. CLOUD-765 measured that a claude.ai connector's per-tool control set to
# `ask` prompts in every permission mode and that **a `PreToolUse` hook returning
# `allow` does not skip that prompt**; this session's injected config sets every
# toolbox tool, `unsubscribe_pr_activity` among them, to `always_ask`. So the arm
# asserted an authority it did not hold, and a human paid one approval click per
# landing while believing the file had removed it.
#
# What replaced it is an actor, not a louder claim: `pr-unsubscribed drop` makes
# the call from a task, over the session-ingress-authenticated `/github/mcp`
# route, where no permission control applies because no tool call is mediated. A
# verb no agent needs to call needs no pre-approval, and an agent that calls it by
# hand should see the prompt the connector is in fact going to show.
#
# `ALLOW_SUFFIXES` stays as an empty declaration rather than being deleted
# outright, because `--covers-allow` publishes it to `mcp-allow-check`, whose
# CLOUD-790 predicate refuses any suffix listed there that the live connector does
# not set to `always_allow`. Re-adding a verb here is therefore gated by the same
# measurement that removed this one, instead of by whoever reads this header.
#
# THE SUBSTRING HAZARD, AND WHAT NOW CARRIES IT ALONE.
# `unsubscribe_pr_activity` ENDS WITH `subscribe_pr_activity`, so an unbounded
# `*subscribe_pr_activity` test matches BOTH and denies a call this file has no
# verdict on — identical to the hazard `closing-key-check` records against its own
# `DO-NOT-CLOSE` marker, where "the opt-out was unusable exactly when it was
# written correctly, and it failed as the inverse of the author's intent rather
# than as a refusal, which is the silent direction."
#
# There used to be two defences here and the allow arm was the redundant one. The
# structural defence is the only one left and always was the mechanism: the deny
# arm is LEFT-BOUNDED on `__`, so `…__unsubscribe_pr_activity` cannot match
# `*__subscribe_pr_activity` at all — the boundary character is `u`, not `s`.
# With the allow arm gone the suite's bound rows (`…_v2`, `resubscribe_…`, and
# `unsubscribe_pr_activity` under both spellings) are load-bearing rather than
# corroborating: they are what stands between this file and denying the wrong verb.
#
# Pointer-only (non-negotiable 4): the decision names the verb and the rule, never
# the payload.
#
# `--covers` prints the tool suffixes this file decides, one per line, so
# `mcp-allow-check` can bind a deny rule to its coverage without grepping this
# file's `case` statements. One authority per fact. `--covers-allow` prints the
# ALLOW half alone, which is the half a connector control can silently override —
# see the CLOUD-790 note above.
#
# Exit 0 always — a guard renders its verdict in the JSON, never in the status.
# FAILS OPEN on everything it cannot establish, and on BATTEN_CONNECTOR_VERB_BYPASS=1.
#
# The mutation re-adds the removed allow arm, which is the regression CLOUD-790
# cost a human one click per landing: the suffix reads as pre-approved here while
# the connector prompts anyway. Only an unsubscribe row can catch it — every deny
# row passes under it — which is why those rows stay in the suite under both
# spellings even though this file no longer decides them.
#MUTANT unsubscribe-repreapproved|s@^ALLOW_SUFFIXES=""@ALLOW_SUFFIXES="unsubscribe_pr_activity"@|an unsubscribe under the readable name is left undecided
set -uo pipefail

# Empty by measurement, not by omission — see the CLOUD-790 note above. Anything
# added here must be a verb the live connector sets to `always_allow`, and
# `mcp-allow-check` refuses the commit if it is not.
ALLOW_SUFFIXES=""
DENY_SUFFIXES="subscribe_pr_activity send_later create_trigger"

if [ "${1:-}" = "--covers" ]; then
	for suffix in $ALLOW_SUFFIXES $DENY_SUFFIXES; do
		printf '%s\n' "$suffix"
	done
	exit 0
fi

if [ "${1:-}" = "--covers-allow" ]; then
	for suffix in $ALLOW_SUFFIXES; do
		printf '%s\n' "$suffix"
	done
	exit 0
fi

# CLOUD-479's pairing, declared rather than discovered: registered BY PATH, so
# mise's `"aqua:jqlang/jq"` pin does not reach it and `jq` is whatever the ambient
# PATH holds. Every read below fails open, so an absent parser would ALLOW
# silently — the one outcome a guard must never reach by accident. Say so on
# stderr and get out of the way; exit 2 is a DENY on this event and a broken
# toolchain must not take that channel.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: connector-verb-guard: no jq on PATH — this guard is registered by path, so it does not get mise's pinned jq. It is checking NOTHING and allowing every call. Run: mise install" >&2
	exit 0
fi

[ -n "${BATTEN_CONNECTOR_VERB_BYPASS:-}" ] && exit 0

raw=$(cat) || exit 0

tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[ -n "$tool" ] || exit 0

decide() {
	jq -n --arg d "$1" --arg r "$2" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: $d,
    permissionDecisionReason: $r
  }
}'
	exit 0
}

# ALLOW FIRST, and the loop is empty today. Kept ahead of the deny arm so a suffix
# added back here cannot be caught by the deny arm's substring on its way in — the
# ordering was never the defence against that (the `__` bound is), but a reader
# adding a verb should not have to know which of the two is load-bearing.
for suffix in $ALLOW_SUFFIXES; do
	case "$tool" in
	*__"$suffix" | "$suffix")
		decide allow "connector-verb-guard: $suffix is pre-approved by .claude/settings.json's committed policy, applied here by tool-name suffix so the verdict survives the exposed server name changing."
		;;
	esac
done

# Left-bounded on `__` so it cannot reach back across the word boundary into
# `unsubscribe_pr_activity`. The bare-name arm is for a host that exposes a verb
# with no server prefix at all.
for suffix in $DENY_SUFFIXES; do
	case "$tool" in
	*__"$suffix" | "$suffix")
		decide deny "connector-verb-guard: $suffix is denied by AGENTS.md — no heartbeats (send_later/Routines/timers) and no babysitting a PR. Landing is driven by \`mise run land\`, which laps fetch -> rebase -> verify -> push -> ci-wait -> fast-forward by itself; a webhook's silence is not success. Bypass with BATTEN_CONNECTOR_VERB_BYPASS=1 when a human has asked for this specific call."
		;;
	esac
done

exit 0
