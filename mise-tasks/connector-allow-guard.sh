#!/usr/bin/env bash
#MISE description="PreToolUse hook body: apply the committed connector permissions to whichever server name the host exposed, per call (CLOUD-191)"
#
# CLOUD-191. The adapter half. `connector-allow-resolve` owns the decision and its
# reasoning; this file owns only the envelope: decode the hook payload, ask the
# resolver, render the answer in the `PreToolUse` shape the other guards use.
#
# PER CALL, NEVER ONCE, and that is the whole reason this is a hook rather than a
# settings write. The flip is bidirectional and mid-session — one session went
# readable -> UUID -> readable — so anything that resolves a name once and caches
# it for the session is wrong for part of that session by construction. This
# file's predecessor was specified as a `SessionStart` repair; that shape cannot
# work, and the issue's own Ready block refuses it. Nothing here is written,
# cached, or persisted, so nothing has to land in time.
#
# ALLOW IS A DECISION, not an omission — the same note `connector-verb-guard`
# carries. Emitting nothing leaves the ordinary permission flow to prompt, which
# is exactly the failure during a UUID episode. Pre-approving needs
# `hookSpecificOutput.permissionDecision: "allow"` on stdout.
#
# `silence` is emitted as literally nothing, which is not the same as `allow`: it
# hands the call back to the ordinary flow, so a name this file cannot resolve
# behaves exactly as it does today.
#
# Exit 0 always — a guard renders its verdict in the JSON, never in the status,
# because a non-zero exit is a DENY on this event and a broken toolchain must not
# take that channel. FAILS OPEN on everything it cannot establish, and on
# BATTEN_CONNECTOR_ALLOW_BYPASS=1.
#
# Pointer-only (non-negotiable 4): the reason names the alias and the verb, never
# the live key and never the payload.
#
# The mutation drops the allow arm, so a translated call falls through UNDECIDED
# and the approval prompt this file exists to remove comes back. Every deny row
# still passes under it — only an allow row under a flipped name can catch it,
# which is what makes those rows the suite's spine.
#MUTANT translated-allow-not-emitted|s@^allow)$@allow-never)@|a committed allow is emitted as an allow under a flipped name
set -uo pipefail

[ -n "${BATTEN_CONNECTOR_ALLOW_BYPASS:-}" ] && exit 0

# Registered BY PATH, so mise's pinned jq does not reach this. Every read below
# fails open, so an absent parser would leave every call undecided — which is
# today's behaviour rather than a new hazard, but say so, because a guard that is
# silently checking nothing is the shape CLOUD-418 exists to refuse.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: connector-allow-guard: no jq on PATH — this guard is registered by path, so it does not get mise's pinned jq. It is translating NOTHING, and a flipped server name will prompt. Run: mise install" >&2
	exit 0
fi

raw=$(cat) || exit 0
tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[ -n "$tool" ] || exit 0

# Relative, because a hook's cwd is the project root and `CLAUDE_PROJECT_DIR` is
# only conditionally set — the same reasoning `session-start.sh` records for
# `reclaim-census`.
resolver="$(dirname -- "${BASH_SOURCE[0]}")/connector-allow-resolve"
[ -x "$resolver" ] || exit 0

read -r verdict alias < <("$resolver" "$tool" 2>/dev/null) || exit 0
[ -n "${verdict:-}" ] || exit 0

decide() { # decide <allow|deny> <reason>
	jq -n --arg d "$1" --arg r "$2" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: $d,
    permissionDecisionReason: $r
  }
}'
	exit 0
}

verb=${tool##*__}

case "$verdict" in
allow)
	decide allow "connector-allow-guard: .claude/settings.json already allows ${verb} on ${alias}. The host is exposing that server under a different name this session, so the committed rule does not match it literally — this applies the committed verdict, and grants nothing the file does not already state (CLOUD-191)."
	;;
deny)
	decide deny "connector-allow-guard: .claude/settings.json denies ${verb} on ${alias}, and the host is exposing that server under a different name this session, so the committed deny rule does not match it literally. AGENTS.md's ban on babysitting timers rests on this refusal (CLOUD-191)."
	;;
esac

# silence: emit nothing and let the ordinary permission flow decide.
exit 0
