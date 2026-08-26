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
# THE REPLY GOES TO BATTEN, NEVER TO THE HOST. This file is dispatched BY
# `batten hook` as a `[[hook.handler]]` row (CLOUD-312 row 5), and the door's
# third contract item is that stdout is INTERPRETED rather than forwarded: a
# `hookSpecificOutput` document written here is `Violation::ImpersonatedHost`,
# reported and dropped. It wrote one for its whole life behind the door.
#
# MEASURED 2026-08-26 on the live wiring, which is why this is a correction and
# not a tidy-up. A `send_later` call under a UUID alias made this guard emit its
# deny document; `batten hook` answered on stderr with `hook.handler
# connector-allow-guard: wrote a host decision document`, and the refusal that
# actually reached the host came from an unrelated engine row that happens to
# cover the same tool. EVERY deny in the committed table is covered that way
# today, which is exactly why a dropped verdict looked like a working one.
#
# So a refusal is exit 2 with its reason on stderr, and the engine renders it per
# harness — this file no longer knows or names Claude's spelling.
#
# ALLOW IS A DECISION, not an omission — the same note `connector-verb-guard`
# carries. Emitting nothing leaves the ordinary permission flow to prompt, which
# is exactly the failure during a UUID episode.
#
# AND THE DOOR HAS NO CHANNEL FOR IT, WHICH IS A STATED LOSS RATHER THAN AN
# OMISSION. `hook.rs` encodes `deny` and `ask` and nothing else — there is no
# `Outcome` a handler can return that becomes `permissionDecision: "allow"`, and
# `AdvisoryReach` for this host does not list the pre-tool event either, so an
# advisory here has no model-facing surface to land on.
#
# WHAT IT DOES INSTEAD, MEASURED RATHER THAN ASSUMED: the engine writes it to its
# own stderr, which this host shows in the transcript and not to the model. So
# the allow arm emits advisory text — inert for the approval prompt CLOUD-191
# exists to remove, visible to a human reading the session, correct under the
# contract, and the shape that starts working the day either channel reaches
# pre-tool. What it is NOT is a document that gets dropped, because a dropped
# allow and a delivered one are byte-identical from in here. CLOUD-898 owns the
# door and therefore the missing channel; the trace is recorded there.
#
# `silence` is emitted as literally nothing, which is not the same as `allow`: it
# hands the call back to the ordinary flow, so a name this file cannot resolve
# behaves exactly as it does today.
#
# FAILS OPEN on everything it cannot establish, and on
# BATTEN_CONNECTOR_ALLOW_BYPASS=1: every could-not-look path exits 0 silently,
# because exit 2 is the deny code behind the door as well as in front of it and a
# broken toolchain must not take that channel.
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

[[ -n "${BATTEN_CONNECTOR_ALLOW_BYPASS:-}" ]] && exit 0

# Mise's pinned jq does not reach this. Going behind the door did not change
# that: `batten hook` is itself invoked by the harness rather than through mise,
# so a dispatched handler inherits the harness's PATH exactly as a by-path
# registration did. Every read below fails open, so an absent parser would leave
# every call undecided — which is today's behaviour rather than a new hazard, but
# say so, because a guard that is silently checking nothing is the shape
# CLOUD-418 exists to refuse.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: connector-allow-guard: no jq on PATH — this guard inherits the harness's PATH, not mise's, so mise's pinned jq does not reach it. It is translating NOTHING, and a flipped server name will prompt. Run: mise install" >&2
	exit 0
fi

raw=$(cat) || exit 0
tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[[ -n "$tool" ]] || exit 0

# Relative, because a hook's cwd is the project root and `CLAUDE_PROJECT_DIR` is
# only conditionally set — the same reasoning `session-start.sh` records for
# `reclaim-census`.
resolver="$(dirname -- "${BASH_SOURCE[0]}")/connector-allow-resolve.sh"
[[ -x "$resolver" ]] || exit 0

read -r verdict alias < <("$resolver" "$tool" 2>/dev/null) || exit 0
[[ -n "${verdict:-}" ]] || exit 0

decide() { # decide <allow|deny> <reason>
	case "$1" in
	deny)
		printf '%s\n' "$2" >&2
		exit 2
		;;
	*)
		printf '%s\n' "$2"
		exit 0
		;;
	esac
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
