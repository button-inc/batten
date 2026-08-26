#!/usr/bin/env bash
#MISE description="Gate: no MCP allow rule in .claude/settings.json is silently skipped by the CLI"
#
# A permission rule that grants nothing is silent by construction: the only
# symptom is an approval prompt on every call, which reads as harness behaviour
# rather than as a settings bug. That silence is what earns a gate.
#
# Three predicates, all pure functions of the settings file:
#
#   unanchored-allow-glob     an allow rule whose glob reaches the server
#                             segment. The CLI accepts a tool-name glob only
#                             after a literal `mcp__<server>__` prefix; anything
#                             broader is skipped with a warning, so it reads as
#                             a grant and is not one.
#
#   ungranted-enabled-server  a server this repo turns on in
#                             `enabledMcpjsonServers` that no allow rule names.
#                             The same silence from the other end: the first
#                             predicate catches a grant matching no tool, this
#                             one catches a server with no grant at all. Serena
#                             shipped that way — `.mcp.json` declared it,
#                             `enabledMcpjsonServers` turned it on, and no allow
#                             rule mentioned it, so every `mem:` read AGENTS.md
#                             mandates stalled behind an approval prompt this
#                             repo had already decided to give.
#
#   uncovered-connector-deny  a deny naming ONE host-supplied server and ONE
#                             tool, both literally, that no suffix-matching
#                             guard covers. Detail and the measurement are
#                             beside the predicate at the foot of this file.
#
# A deny may still glob freely — `mcp__*` is a broad prohibition rather than a
# misspelled narrow one, and a deny that OVER-matches fails closed. What the
# third predicate added is the opposite direction: a deny that UNDER-matches,
# because it spells a connector name the host has since changed, fails open and
# silently. That distinction is the whole of its scope.
#
# Reads no network. The first three predicates take the settings file as their
# whole input, so they answer the same way in a hook, on CI, and in a test; the
# fourth (CLOUD-684) reads which servers this session attached and is gated
# behind `--session` for exactly that reason.
#
# The declared exemption `hook-pin-check` honours, beside the assertion it
# describes rather than in a list that could drift from it.
#MUTANT allow-check-ignores-policy|s/^\t\t\t\[\[ "\$policy" = always_allow \]\].*$/\t\t\tcontinue/|sets to ask is unenforceable
#PIN-OK: jq
set -euo pipefail

# REGISTERED BY PATH on `UserPromptSubmit`, which does not get mise's env, so the
# pinned `jq` becomes whatever the ambient PATH offers — or nothing. Every read
# below falls back through `2>/dev/null`, so an absent jq would report a clean
# settings file while checking none of it. That is the trade CLOUD-479 refuses:
# a latency fix must not turn a pinned dependency into a silent fail-open.
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: mcp-allow-check: no jq on PATH — every read here would fail into a silent pass, so this gate is checking NOTHING. Run it through \`mise run mcp-allow-check\`, or install jq." >&2
	exit 2
fi

# TWO SCOPES IN ONE FILE, and the flag is what keeps them apart. The first three
# predicates are pure functions of the committed settings — properties of the
# COMMIT, so they belong in the hk gate and in CI. The fourth reads which servers
# this session attached, a property of the WORLD, and a commit gate that consulted
# it would fail a branch for something the branch did not cause
# (.claude/rules/toolchain.md, "which of the two it is"). So `--session` is
# required to run it, and only the `UserPromptSubmit` registration passes it.
session=0
settings=".claude/settings.json"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--session)
		session=1
		shift
		;;
	*)
		settings="$1"
		shift
		;;
	esac
done

# A missing or unparseable settings file is not this gate's business to
# adjudicate; pkl-check and the JSON tooling own that. Fail open, loudly enough
# to not look like a pass we computed.
if [[ ! -f "$settings" ]]; then
	echo "mcp-allow-check: no $settings — nothing to check"
	exit 0
fi
if ! allows=$(jq -e -c '[.permissions.allow // [] | .[] | select(type == "string")]' "$settings" 2>/dev/null); then
	echo "::error:: $settings is not readable JSON with a permissions.allow list" >&2
	exit 2
fi

fail=0
report() {
	[[ "$fail" = 0 ]] && echo "::error:: MCP permission defects in $settings (see mem:toolchain-and-hooks):" >&2
	printf '  %s\n' "$1" >&2
	fail=1
}

while IFS= read -r rule; do
	[[ -n "$rule" ]] || continue
	case "$rule" in
	mcp__*) ;;
	*) continue ;;
	esac
	# Legal only after a literal `mcp__<server>__` prefix: the server segment
	# must be glob-free so the rule names a server that was actually configured.
	server=${rule#mcp__}
	server=${server%%__*}
	case "$server" in
	*'*'*) report "$rule — the server segment cannot be a glob; the CLI skips this rule with a warning and it grants nothing" ;;
	esac
done < <(jq -r '.[]' <<<"$allows")

# A bare `*` or `B*` in the tool position of a non-MCP rule is a different
# question; this gate owns MCP only. But an allow list containing a top-level
# unanchored glob is the same silent-grant failure, so name it.
while IFS= read -r rule; do
	case "$rule" in
	'*') report "$rule — an unanchored allow glob is skipped with a warning; it auto-approves nothing" ;;
	esac
done < <(jq -r '.[]' <<<"$allows")

# The other end of the same silence: a server this repo turns on that no allow
# rule names. Answerable from the file alone — unlike the connector-name question
# below, `enabledMcpjsonServers` is the repo's own declaration of what is on.
while IFS= read -r server; do
	[[ -n "$server" ]] || continue
	granted=0
	while IFS= read -r rule; do
		case "$rule" in
		mcp__*) ;;
		*) continue ;;
		esac
		rule_server=${rule#mcp__}
		rule_server=${rule_server%%__*}
		[[ "$rule_server" = "$server" ]] && granted=1
	done < <(jq -r '.[]' <<<"$allows")
	[[ "$granted" = 1 ]] ||
		report "$server — enabledMcpjsonServers turns this server on and no allow rule names it; every call to it prompts"
done < <(jq -r '(.enabledMcpjsonServers // empty) | if type == "array" then .[] else empty end' "$settings" 2>/dev/null)

# NOT checked: whether an allowed server also has a `mcp__claude_ai_<server>__*`
# companion. An earlier version demanded one, on the reasoning that a claude.ai
# connector is exposed under that name — true of the local CLI, whose own
# built-in allowlist carries `mcp__claude_ai_Slack__slack_send_message`.
#
# But CLOUD-178 measured the exposed name to be chosen per registration episode
# by the host, not fixed: in Claude Code on the web, connectors arrive as
# explicit `--mcp-config` entries and appear as `mcp__<server>__*`, and after a
# mid-session re-register as `mcp__<uuid>__*`. So the companion this gate used
# to demand is inert in a web session, and the name that would actually help is
# an account-specific UUID that rule 1 keeps out of committed config.
#
# A gate may only assert what it can verify from the repo. The connector-name
# question cannot be, and belongs in user-level settings — see CLOUD-178.

# --- an under-matching DENY, which is the direction that fails open -----------
#
# The paragraph above still holds: this gate cannot know which name a connector
# is live under. What it CAN decide from the repo alone is whether a rule is
# being RELIED ON for a server the repo never declares.
#
# MEASURED 2026-08-19, on this gate's own settings file at `d671184`. Four deny
# rules named `mcp__Claude_Code_Remote__*` and `mcp__github__*`; the session that
# wrote them had those connectors exposed as `mcp__bf7c680d-…__*` and
# `mcp__cc451d34-…__*`, so three of the four matched nothing. The gate passed,
# because every rule was well-SHAPED. A deny that names no live tool reads as a
# prohibition and enforces nothing.
#
# WHY DENIES AND NOT ALLOWS, which is the whole of the new predicate's scope. The
# two fail in opposite directions. An under-matching ALLOW fails closed — the call
# stops at an approval prompt, a human sees it, and the compensating control
# CLOUD-178 already records ("the failure is loud to the human even though it is
# silent to the agent") applies. An under-matching DENY fails OPEN, silently, and
# no one is prompted about a prohibition that quietly stopped applying. Only the
# second needs a gate, and scoping to it is what lets this land without a waiver
# for every pre-existing allow rule.
#
# COVERAGE IS DECLARED, NEVER PARSED. A guard that decides a verb by tool-name
# SUFFIX works under any exposed server name, which is the portable form of this
# rule — `issue-read-guard` and `board-move-guard` have matched `*save_issue` that
# way all along. Each such guard prints the suffixes it owns via `--covers`, and
# this gate takes the union. Grepping a neighbour's `case` statements instead
# would be a second authority for a fact the guard already states.
#
# A server the repo DOES declare (`.mcp.json` / `enabledMcpjsonServers`) keeps a
# stable name by construction, so its deny rules need no guard.
declared=$( (
	jq -r '(.enabledMcpjsonServers // empty) | if type == "array" then .[] else empty end' "$settings" 2>/dev/null
	jq -r '(.mcpServers // {}) | keys[]' .mcp.json 2>/dev/null
) | sort -u)

# STDIN IS CLOSED FOR THE PROBE, and that is not a tidiness detail. A guard that
# does not know `--covers` falls through to its `raw=$(cat)` and blocks forever
# waiting for a payload that will never come — this gate hung the whole suite
# exactly once, at the two-minute harness kill, before the redirect was added.
# The output is filtered to bare tool-name shapes so a guard that answers with a
# usage line or an `::error::` cannot inject a spurious "coverage".
# THE ENGINE IS ONE OF THE SOURCES NOW (CLOUD-312 row 4). A `tool`-keyed row
# decides a verb by the same suffix rule a guard did — `Rule::selects_tool` matches
# the whole name or the whole final `__`-delimited segment — so the rows cover
# exactly what the guard's `--covers` used to declare. Asking the engine keeps this
# ONE authority: the alternative was grepping `batten.toml` for a fact the loader
# already holds, which is the second-authority shape the paragraph above refuses.
#
# The union, not a replacement: a guard that still publishes coverage is still
# read, so this survives the rest of the wave retiring one row at a time.
#
# AN ABSENT BINARY IS COULD-NOT-LOOK, NOT AN EMPTY COVERAGE SET, and this clause
# once said the opposite: "a `covered` set that is too SMALL over-reports rather
# than under-reports, which is the safe direction". That is the wrong direction for
# a gate, and CI measured it. While `connector-verb-guard` still existed its
# `--covers` carried these suffixes, so an absent binary cost nothing; the moment
# row 4 retired that guard the engine became the ONLY source, and on a runner with
# no `batten` installed the set came back empty and every uncovered deny was
# reported — the gate failing a clean tree, twice, on runs 32905035350 and
# 32912005947.
#
# So the engine read's own status is kept. It succeeded: judge coverage. It could
# not be performed at all: say so and skip THIS predicate, which is exit 0 and a
# stated reason rather than a verdict nothing backs (house-style §6's could-not-look
# channel, and non-negotiable rule 3 — a gate decides over an object it can read).
# The other predicates here read the settings file and are unaffected either way.
engine_read=0
if ! covered_engine=$(
	read -r -a batten_bin <<<"${BATTEN_BIN:-batten}"
	"${batten_bin[@]}" policy tools 2>/dev/null
); then
	engine_read=1
fi

covered=$( (
	printf '%s\n' "$covered_engine"
	for guard in "$(dirname "$0")"/*-guard.sh; do
		[[ -x "$guard" ]] || continue
		"$guard" --covers </dev/null 2>/dev/null || true
	done
) | { grep -E '^[a-z][a-z0-9_]*$' || true; } | sort -u)

if [[ "$engine_read" != "0" ]]; then
	# COULD NOT LOOK, so nothing is judged here. The engine is the only source of
	# these suffixes since row 4 retired the guard that published them, so an
	# unavailable binary means the coverage question has no answer — and an
	# unanswered question is not a finding. Said once, on stdout with the rest of
	# this file's summary lines, so the skip is visible rather than a silent pass.
	echo "mcp-allow-check: deny coverage not judged — \`${BATTEN_BIN:-batten} policy tools\` could not be read, and it is the only source of the covered suffixes"
fi

while IFS= read -r rule; do
	[[ "$engine_read" == "0" ]] || break
	[[ -n "$rule" ]] || continue
	case "$rule" in
	mcp__*) ;;
	*) continue ;;
	esac
	rule_server=${rule#mcp__}
	rule_server=${rule_server%%__*}
	suffix=${rule##*__}
	# A GLOB IN EITHER SEGMENT IS THE OTHER QUESTION, and the header above already
	# answers it: "a deny may glob freely". `mcp__*` is a broad prohibition, not a
	# misspelled narrow one, and there is no suffix for a guard to cover. The
	# predicate here is only about a deny that names ONE server and ONE tool, both
	# literally — the shape that looks precise and silently addresses nothing.
	case "$rule_server$suffix" in
	*'*'*) continue ;;
	esac
	# Declared server: the name is the repo's own and cannot drift under it.
	grep -qxF "$rule_server" <<<"$declared" && continue
	grep -qxF "$suffix" <<<"$covered" && continue
	report "$rule — a deny on a host-supplied connector, whose exposed name the host chooses per registration episode (CLOUD-178). No suffix-matching guard covers \`$suffix\`, so this rule reads as a prohibition and enforces nothing the moment the connector comes back under a different name."
done < <(jq -r '[.permissions.deny // [] | .[] | select(type == "string")] | .[]' "$settings")

# --- an ALLOW rule the connector control cannot honour (CLOUD-765) -----------
#
# THIS REPLACES CLOUD-684's PREDICATE, and the reversal is the finding. That one
# reported an allow rule naming a server not attached under that name. It is
# false wherever `connector-allow-guard` is wired: CLOUD-191 applies the
# committed verdict to whichever name the host exposed, per call, so a rule that
# names the committed alias DOES take effect. A gate reporting a defect another
# mechanism already repairs is noise, and noise is how a gate gets switched off.
#
# What survives is the finding no translation can repair. A claude.ai connector
# carries a PER-TOOL control owned by the organization, and for a tool set to
# `ask` the client prompts on every call — in every permission mode, with no
# remember-my-choice option, and "Allow rules that match the tool don't skip the
# prompt either" (code.claude.com/docs/en/mcp, per-tool controls on claude.ai
# connectors). That setting is the generated config's `permission_policy`, read
# at startup and enforced LOCALLY.
#
# MEASURED ON EVERY REACHABLE LEVER, 2026-08-20, before this was believed: the
# generated config edited mid-session, a gitignored overlay, a rule naming the
# LIVE identifier in the committed settings file forty minutes before a session
# started, and a `PreToolUse` hook returning `allow`. All four refused. Beside
# them the Linear connector, whose tools are set to allow, passed throughout —
# same session, same transport. So the committed rule is not weak or misspelled;
# it is structurally incapable of what it says, and only the connector control
# can change that.
#
# THE FINDING NAMES THE REMEDY, deliberately. An agent told only "this rule does
# not work" reaches for the file it can write, which is how four dead ends got
# built here. The remedy is the connector's Tool permissions, and it is not in
# this repository.
#
# A DENY IS NEVER REPORTED. The control chooses ask versus allow and never
# widens a deny — measured the same session, the three tools this file denies
# were absent from the session's tool list entirely. Flagging one would say
# "delete the rules doing the only enforcement there is", so the predicate is
# one-directional by construction.
#
# ONE RESOLVER, AND IT IS NOT THIS FILE'S: `connector-allow-resolve` (CLOUD-191)
# answers which committed server a live name refers to, anchored on the injected
# entry's endpoint rather than its rotating key. A second definition of that fact
# was built here in ignorance of it and is deleted; this reads the survivor.
#
# Fails open with no live session — CI, a bare checkout, a different harness —
# because a connector control is a property of the WORLD, not of the commit
# (.claude/rules/toolchain.md's split), and a gate that cannot look must never
# report a verdict it did not compute.
#
# Pointer-only per non-negotiable rule 4: the server segment, a count and the
# policy token. Never a tool name, a URL, or the `headers` block, which carries
# this session's credentials.
resolve="$(dirname "$0")/connector-allow-resolve.sh"
config="${BATTEN_MCP_CONFIG:-}"
if [[ -z "$config" ]]; then
	for candidate in /tmp/mcp-config-cse_*.json; do
		[[ -f "$candidate" ]] || continue
		config="$candidate"
		break
	done
fi

if [[ "$session" = 1 ]] && [[ -x "$resolve" ]] && [[ -n "$config" ]] && [[ -f "$config" ]]; then
	# The live key → committed alias map, asked of the one authority. A probe verb
	# no rule can name keeps the answer to the alias: the resolver prints
	# `<verdict> <alias>`, and a non-toolbox server answers `-` by design, because
	# a claude.ai connector is authorised at the connector layer rather than by
	# this file.
	while IFS= read -r key; do
		[[ -n "$key" ]] || continue
		alias=$("$resolve" "mcp__${key}____probe__" --config "$config" --settings "$settings" </dev/null 2>/dev/null | cut -d' ' -f2)
		[[ -n "$alias" ]] && [[ "$alias" != "-" ]] || continue
		# Every tool this alias's allow rules name, judged against the policy the
		# host wrote for it. ONE FINDING PER ALIAS AND A COUNT, never a line per
		# rule: six rules against one connector setting are one thing to fix, and
		# a count is what non-negotiable rule 4 asks for anyway.
		blocked=0
		policies=""
		while IFS= read -r verb; do
			[[ -n "$verb" ]] || continue
			policy=$(jq -r --arg s "$key" --arg t "$verb" '
			  (.mcpServers[$s].tools // []) | map(select(.name == $t)) | .[0].permission_policy // ""
			' "$config" 2>/dev/null)
			[[ -n "$policy" ]] || continue
			[[ "$policy" = always_allow ]] && continue
			blocked=$((blocked + 1))
			case " $policies " in
			*" $policy "*) ;;
			*) policies="${policies}${policies:+,}$policy" ;;
			esac
		done < <(jq -r --arg p "mcp__${alias}__" '.[] | select(startswith($p)) | sub("^" + $p; "")' <<<"$allows" | grep -vF '*' | sort -u)
		[[ "$blocked" = 0 ]] ||
			report "$alias — $blocked allow rule(s) name a tool the connector sets to \`$policies\`, and an allow rule never skips that prompt. Fix it at the connector's Tool permissions, not in $settings (CLOUD-765)."
	done < <(jq -r '(.mcpServers // {}) | keys[]' "$config" 2>/dev/null)
fi

# --- a GUARD ALLOW ARM the connector control cannot honour (CLOUD-790) --------
#
# THE PREDICATE ABOVE IS BLIND TO THIS, and the blindness is what it cost. It
# judges allow RULES, resolved through `connector-allow-resolve`, which answers
# only for the toolbox alias — every other endpoint is silence by design, because
# translating a claude.ai connector's name would grant what the committed file
# does not. So an `always_ask` tool is reported only if some rule in this file
# names it under `mcp__Claude_Code_Remote__`.
#
# MEASURED 2026-08-20. `unsubscribe_pr_activity` was set to `always_ask` on the
# live connector and prompted on every landing. No rule here named it under that
# alias — the one committed grant spelled the `github` server, which the injected
# config exposes with an empty `tools` array — so the predicate above passed, and
# went on passing while a human clicked through one approval per PR. What actually
# claimed the pre-approval was `connector-verb-guard`'s ALLOW ARM, which no gate
# reads at all: a hook's `permissionDecision: "allow"` is not a rule in this file
# and is not visible to a rule-shaped check.
#
# So this reads the arm. A guard publishes its pre-approved suffixes through
# `--covers-allow` — the same declared-coverage contract the deny predicate uses,
# for the same reason: grepping a neighbour's `case` statements would be a second
# authority for a fact the guard already states. Each suffix is looked up in EVERY
# injected server's tool list, not just the toolbox's, because a hook decides by
# suffix and therefore spans every server the host exposed.
#
# ONE-DIRECTIONAL, like its neighbour. A tool the connector sets to `always_allow`
# is silent; anything else is reported, since `ask` is the only other policy that
# has been observed and a policy this file does not recognise is not one it should
# assume a hook can beat. A DENY arm is never judged — a connector control chooses
# ask versus allow and never widens a deny, so a deny arm enforces regardless.
#
# THE FINDING NAMES THE REMEDY, and the remedy is not an edit to this repository:
# either the connector's Tool permissions change, or the arm comes out and the
# work is done by something that is not a mediated tool call — which is what
# `pr-unsubscribed drop` now is.
#
# Fails open with no live session, same as the predicate above and for the same
# reason: a connector control is a property of the WORLD, not of the commit.
#
# Pointer-only per non-negotiable rule 4: the suffix, the policy token and a
# count. Never a server key, a URL, or the `headers` block.
#
# The mutation accepts any policy, which is the whole predicate: with it in place
# the `always_ask` arm that cost a click per landing reads as clean.
#MUTANT guard-allow-ignores-policy|s/^\t\t\t\[\[ "\$arm_policy" = always_allow \]\] && continue$/\t\t\tcontinue/|a pre-approved suffix the connector sets to ask is refused
if [[ "$session" = 1 ]] && [[ -n "$config" ]] && [[ -f "$config" ]]; then
	# STDIN IS CLOSED FOR THE PROBE, for the reason the deny predicate records: a
	# guard that does not know this flag falls through to its `raw=$(cat)` and
	# blocks forever. The output is filtered to bare tool-name shapes so a usage
	# line cannot inject a spurious suffix.
	# EMPTY IS THE HEALTHY STATE and must not be an error. Today no guard
	# pre-approves anything, so the `grep` matches nothing and exits 1 — under
	# `set -e` that killed the whole gate silently, with no finding and no summary
	# line, which is the fail-shaped-as-pass this file exists to refuse. The
	# fallback is what keeps "nothing to judge" distinct from "could not judge".
	# THE SEAM IS WHAT MAKES THIS TESTABLE AT ALL. Today no guard publishes a
	# pre-approved suffix — that is the fixed state — so a suite reading the real
	# guard directory would exercise nothing and pass whatever the predicate did.
	# `BATTEN_GUARD_DIR` lets a fixture supply a guard that does publish one,
	# which is the only way a row can discriminate. Production never sets it.
	preapproved=$(for guard in "${BATTEN_GUARD_DIR:-$(dirname "$0")}"/*-guard.sh; do
		[[ -x "$guard" ]] || continue
		"$guard" --covers-allow </dev/null 2>/dev/null || true
	done | grep -E '^[a-z][a-z0-9_]*$' | sort -u) || preapproved=""

	while IFS= read -r suffix; do
		[[ -n "$suffix" ]] || continue
		blocked=0
		policies=""
		while IFS= read -r arm_policy; do
			[[ -n "$arm_policy" ]] || continue
			[[ "$arm_policy" = always_allow ]] && continue
			blocked=$((blocked + 1))
			case " $policies " in
			*" $arm_policy "*) ;;
			*) policies="${policies}${policies:+,}$arm_policy" ;;
			esac
		done < <(jq -r --arg t "$suffix" '
		  (.mcpServers // {})
		  | to_entries[]
		  | (.value.tools // [])
		  | map(select(.name == $t))
		  | .[]
		  | .permission_policy // empty
		' "$config" 2>/dev/null)
		[[ "$blocked" = 0 ]] ||
			report "$suffix — a guard pre-approves this tool, and the connector sets it to \`$policies\` on $blocked exposed server(s). A hook's \`permissionDecision: allow\` never skips that prompt, so the arm claims an authority it does not hold. Fix it at the connector's Tool permissions, or drop the arm and do the work off the mediated path (CLOUD-790)."
	done <<<"$preapproved"
fi

# SILENCE ON THE NORMAL PATH (CLOUD-891). This printed a 60-word success line at
# every `UserPromptSubmit`. See `mcp-attach-check` for the argument; the refusals
# above are untouched.
exit "$fail"
