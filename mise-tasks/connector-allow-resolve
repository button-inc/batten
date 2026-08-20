#!/usr/bin/env bash
#MISE description="The pure decision behind connector-allow-guard: apply the committed permissions to whichever server name the host exposed, resolved through the injected config's endpoint (CLOUD-191)"
#
# CLOUD-191. A `.claude/settings.json` permission rule names its server as a
# LITERAL — `mcp-allow-check` refuses a glob in that segment, correctly, because
# the CLI skips such a rule and it grants nothing. But the harness's toolbox
# server is exposed under a name the HOST chooses per registration episode:
# `mcp__Claude_Code_Remote__create_session` at session start, and
# `mcp__<uuid>__create_session` after a mid-session re-register. The literal that
# would match the second is an account-specific identifier, which non-negotiable
# rule 1 keeps out of committed config.
#
# So during a UUID episode the committed file's allow rules grant nothing and its
# deny rules enforce NOTHING, and neither failure is observable to the agent: an
# agent cannot see its own approval prompts. The deny half is the worse one.
# AGENTS.md's ban on babysitting timers rests on `send_later` and `create_trigger`
# being denied, and a deny that under-matches reads as a prohibition while
# enforcing nothing.
#
# WHAT THIS IS NOT. It is not a second policy authority and it grants nothing of
# its own. `.claude/settings.json` remains the only statement of which verbs are
# permitted on which server; this file answers one question — "which committed
# server is the host talking about right now" — and then returns THAT FILE's
# verdict. Every outcome it can produce is one the committed file already states.
#
# ANCHOR ON THE ENDPOINT, NOT THE KEY, and that choice is what makes rule 1
# satisfiable. Each injected entry's `url` carries the real upstream in an
# `mcp_url` query parameter. `https://api.anthropic.com/v1/code/mcp/meta` is a
# public vendor address — stable across containers, identical for every account,
# and therefore committable — where the UUID key beside it is neither. Measured
# 2026-08-19: three servers in one session, keyed `github` (no `mcp_url`),
# `4db58e41-…` (`https://mcp.linear.app/mcp`) and `bf7c680d-…` (the meta endpoint
# below).
#
# ONE ENDPOINT IS ENOUGH, and listing more would be the mistake. Only the toolbox
# server is governed by `permissions.allow`; a claude.ai connector is authorised
# at the connector layer, which is why Linear kept working through both naming
# episodes under a name no committed rule spells (CLOUD-665's useful residue).
# Translating a connector's name would therefore GRANT something the committed
# file does not, which is precisely what this must never do — so every endpoint
# that is not the one below resolves to silence.
#
# DENY IS TESTED BEFORE ALLOW. A rule set that both allows a glob and denies a
# verb under it must deny; testing the other way round would let
# `mcp__Claude_Code_Remote__*` pre-approve `send_later`. Fail closed on the
# ordering, not on the author's care.
#
# Pointer-only (non-negotiable 4): the verdict and the alias resolved to, never a
# key, never a URL, never the payload. A UUID is the one thing this file exists to
# handle and the one thing it must never print — the suite asserts no UUID shape
# appears in this file's source at all.
#
# Reads no network. The injected config and the settings file are the whole input,
# so the same command answers the same way in a hook, on CI, and in a test.
#
# Usage: mise run connector-allow-resolve <tool-name> [--config <path>] [--settings <path>]
# Prints: `<verdict> <alias>` on stdout, where verdict is allow | deny | silence.
# Exit 0 always — a resolver renders its verdict on stdout, never in the status,
# so a caller cannot mistake "could not look" for "denied".
#
# The mutation makes the deny arm unreachable by testing allow first, which is the
# ordering hazard named above. Every allow row still passes under it; only a row
# that denies a verb covered by a wider allow glob can catch it.
#MUTANT deny-loses-to-allow-glob|s@^return_if_denied$@return_if_allowed@|a deny outranks an allow glob
set -uo pipefail

# The toolbox server, as a public vendor endpoint and the portable alias the
# committed settings file already spells. These two lines are the whole of this
# file's committed knowledge, and neither is account-specific.
TOOLBOX_ENDPOINT="https://api.anthropic.com/v1/code/mcp/meta"
TOOLBOX_ALIAS="Claude_Code_Remote"

tool=""
config="${BATTEN_MCP_CONFIG:-}"
# The settings seam, symmetric with the config one above. `connector-allow-guard`
# invokes this with neither flag, so without it a suite exercising the guard reads
# the repository's REAL permission rules — and its rows then break whenever those
# rules change, which is what happened when six unenforceable grants were removed
# from the committed file. A test asserting production config is asserting the
# wrong thing. `--settings` still wins over it.
settings="${BATTEN_MCP_SETTINGS:-.claude/settings.json}"

while [ $# -gt 0 ]; do
	case "$1" in
	--config)
		config="${2:-}"
		shift 2 || break
		;;
	--settings)
		settings="${2:-}"
		shift 2 || break
		;;
	*)
		[ -n "$tool" ] || tool="$1"
		shift
		;;
	esac
done

say() { # say <verdict> <alias>
	printf '%s %s\n' "$1" "$2"
	exit 0
}

# Everything below fails to `silence`, which hands the call back to the ordinary
# permission flow. That is the only safe default for a translator: a wrong
# `allow` widens policy and a wrong `deny` blocks work, while a wrong silence
# costs at most the approval prompt that would have happened anyway.
[ -n "$tool" ] || say silence -

# Registered BY PATH through the guard, so mise's `"aqua:jqlang/jq"` pin does not
# reach it — the same declaration `connector-verb-guard` carries for the same
# reason. An absent parser must resolve to silence, never to a grant.
#PIN-OK: jq
command -v jq >/dev/null 2>&1 || say silence -

case "$tool" in
mcp__*__*) ;;
*) say silence - ;;
esac

rest=${tool#mcp__}
server=${rest%%__*}
verb=${rest#*__}
[ -n "$server" ] && [ -n "$verb" ] || say silence -

# The committed file is the authority on which verbs are permitted; this resolves
# only WHICH committed server the live name refers to.
[ -f "$settings" ] || say silence -

# A name the committed file already spells needs no translation — the CLI matches
# it natively, and answering here would put this file in the ordinary path for
# every call it has nothing to say about.
alias=""
if [ "$server" = "$TOOLBOX_ALIAS" ]; then
	say silence "$TOOLBOX_ALIAS"
fi

# Locate the injected config. The host writes one file per session; a local CLI
# session has none, which is not a defect — there is no flip to repair there.
if [ -z "$config" ]; then
	for candidate in /tmp/mcp-config-cse_*.json; do
		[ -f "$candidate" ] || continue
		config="$candidate"
		break
	done
fi
[ -n "$config" ] && [ -f "$config" ] || say silence -

# The endpoint behind the live key. `--arg` rather than interpolation: a server
# segment is host-chosen text and must never be spliced into a jq program.
endpoint=$(jq -r --arg s "$server" '
  (.mcpServers[$s].url // "")
  | if test("mcp_url=") then (capture("mcp_url=(?<u>[^&]*)").u) else "" end
' "$config" 2>/dev/null) || say silence -
[ -n "$endpoint" ] || say silence -

# %-decode just enough to compare: the parameter is a percent-encoded URL.
endpoint=$(printf '%b' "${endpoint//%/\\x}" 2>/dev/null) || say silence -

# Only the toolbox server is governed by `permissions.allow`. Every other
# endpoint — every claude.ai connector — is governed by the connector layer, so
# translating its name would grant what the committed file does not.
[ "$endpoint" = "$TOOLBOX_ENDPOINT" ] || say silence -
alias="$TOOLBOX_ALIAS"

# Does the committed file state a verdict for this verb on this alias? Both the
# exact spelling and the tool-name glob the CLI permits after a literal server
# prefix count, because both are forms the file legitimately uses.
states() { # states <allow|deny>
	# Read into a variable rather than piping into grep: under `pipefail` an
	# early-exiting grep closes the pipe, jq takes SIGPIPE, and a MATCH reports
	# failure — the inversion `pipefail-grep-check` gates, which caught exactly
	# this line before it reached a commit.
	local answer
	answer=$(jq -r --arg a "mcp__${alias}__${verb}" --arg g "mcp__${alias}__*" \
		--arg arm "$1" '
    (.permissions[$arm] // [])
    | map(select(type == "string"))
    | any(. == $a or . == $g)
  ' "$settings" 2>/dev/null) || return 1
	[ "$answer" = true ]
}

return_if_denied() { states deny && say deny "$alias"; }
return_if_allowed() { states allow && say allow "$alias"; }

# Deny first — see the ordering note in the header.
return_if_denied
return_if_allowed

say silence "$alias"
